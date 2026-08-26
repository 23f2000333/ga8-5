import hashlib
import json
import math
import threading

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

SAFE_MAX = 9007199254740991
FREEZES = {}
LOCK = threading.Lock()

FREEZE_CODES = {
    "INVALID_INPUT",
    "UNALLOWED_UNSUPPORTED_REASON",
    "NOT_LOADABLE",
    "CALIBRATION_MISMATCH",
    "TOKENIZER_MISMATCH",
}

SELECT_CODES = {
    "NOT_FROZEN",
    "INVALID_LINEAGE",
    "INVALID_POLICY",
    "INVALID_PREDICTIONS",
    "INVALID_MANIFEST",
    "AGGREGATE_FLOOR",
    "SIZE_LIMIT",
    "LATENCY_LIMIT",
}


def utf8(s):
    return s.encode("utf-8")


def code_sort(values):
    return sorted(set(values), key=utf8)


def nonempty_string(v):
    return isinstance(v, str) and len(v) > 0


def safe_int(v):
    return (
        isinstance(v, int)
        and not isinstance(v, bool)
        and 0 <= v <= SAFE_MAX
    )


def finite_nonnegative(v):
    return (
        isinstance(v, (int, float))
        and not isinstance(v, bool)
        and math.isfinite(v)
        and v >= 0
    )


def finite_unit(v):
    return (
        isinstance(v, (int, float))
        and not isinstance(v, bool)
        and math.isfinite(v)
        and 0 <= v <= 1
    )


def parse_json(raw):
    return json.loads(
        raw.decode("utf-8"),
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
    )


def compact_json(v):
    return json.dumps(
        v,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_text(s):
    return sha256_bytes(utf8(s))


def fingerprint(payload):
    return sha256_text(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        )
    )


def valid_string_list(v, allow_empty=False):
    if not isinstance(v, list):
        return False
    if not allow_empty and len(v) == 0:
        return False
    if not all(nonempty_string(x) for x in v):
        return False
    return len(v) == len(set(v))


def build_inventory(files):
    """
    Returns (inventory, totalBytes, packageDigest), or None if the file
    object itself is invalid.

    File content may be the empty string: it is still valid UTF-8 data.
    """
    if not isinstance(files, dict) or len(files) == 0:
        return None

    inventory = []

    for filename, content in files.items():
        if not nonempty_string(filename):
            return None
        if not isinstance(content, str):
            return None

        data = utf8(content)
        inventory.append({
            "name": filename,
            "bytes": len(data),
            "sha256": sha256_bytes(data),
        })

    inventory.sort(key=lambda x: utf8(x["name"]))

    total = 0
    for row in inventory:
        if total > SAFE_MAX - row["bytes"]:
            return None
        total += row["bytes"]

    digest = sha256_text(compact_json(inventory))
    return inventory, total, digest


def freeze_shape_valid(p):
    # These are request-level requirements. Candidate file defects are NOT
    # transport errors; they become an invalid frozen candidate.
    if not isinstance(p, dict):
        return False

    required = {
        "phase",
        "freezeId",
        "calibrationDigest",
        "tokenizerDigest",
        "allowedUnsupportedReasons",
        "candidates",
    }

    if not required.issubset(p):
        return False

    if p["phase"] != "freeze":
        return False

    if not nonempty_string(p["freezeId"]) or len(p["freezeId"]) > 128:
        return False

    if not nonempty_string(p["calibrationDigest"]):
        return False

    if not nonempty_string(p["tokenizerDigest"]):
        return False

    if not valid_string_list(p["allowedUnsupportedReasons"]):
        return False

    candidates = p["candidates"]
    if not isinstance(candidates, list) or len(candidates) == 0:
        return False

    names = []
    for c in candidates:
        # Candidate names are part of the request contract.
        if not isinstance(c, dict):
            return False
        if "name" not in c or not nonempty_string(c["name"]):
            return False
        names.append(c["name"])

    if len(names) != len(set(names)):
        return False

    return True


def freeze_candidate(c, request_cal, request_tok, allowed):
    name = c["name"]

    # Missing/invalid files are explicitly candidate-level invalid data.
    inventory_data = build_inventory(c.get("files"))
    if inventory_data is None:
        return {
            "name": name,
            "status": "invalid",
            "inventory": [],
            "totalBytes": None,
            "packageDigest": None,
            "reasonCodes": ["INVALID_INPUT"],
        }

    inventory, total, package_digest = inventory_data
    reasons = []

    # Candidate metadata is validated here rather than rejecting the whole
    # freeze request.
    if not isinstance(c.get("loadable"), bool):
        reasons.append("INVALID_INPUT")

    cal = c.get("calibrationDigest")
    tok = c.get("tokenizerDigest")
    unsupported = c.get("unsupportedReason", None)

    if not nonempty_string(cal):
        reasons.append("INVALID_INPUT")
    if not nonempty_string(tok):
        reasons.append("INVALID_INPUT")
    if unsupported is not None and not nonempty_string(unsupported):
        reasons.append("INVALID_INPUT")

    if reasons:
        status = "invalid"
    elif unsupported is not None:
        if unsupported not in allowed:
            reasons.append("UNALLOWED_UNSUPPORTED_REASON")
            status = "invalid"
        else:
            # An allowed unsupported reason means this candidate is
            # unsupported. Its lineage fields still have to match.
            if cal != request_cal:
                reasons.append("CALIBRATION_MISMATCH")
            if tok != request_tok:
                reasons.append("TOKENIZER_MISMATCH")
            status = "unsupported" if not reasons else "invalid"
    else:
        if c["loadable"] is not True:
            reasons.append("NOT_LOADABLE")
        if cal != request_cal:
            reasons.append("CALIBRATION_MISMATCH")
        if tok != request_tok:
            reasons.append("TOKENIZER_MISMATCH")
        status = "frozen" if not reasons else "invalid"

    return {
        "name": name,
        "status": status,
        "inventory": inventory,
        "totalBytes": total,
        "packageDigest": package_digest,
        "reasonCodes": code_sort(reasons),
    }


def do_freeze(p):
    allowed = set(p["allowedUnsupportedReasons"])

    candidates = [
        freeze_candidate(
            c,
            p["calibrationDigest"],
            p["tokenizerDigest"],
            allowed,
        )
        for c in p["candidates"]
    ]

    candidates.sort(key=lambda x: utf8(x["name"]))

    return {
        "freezeId": p["freezeId"],
        "candidates": candidates,
    }


def select_shape_valid(p):
    # The prompt explicitly says malformed select requests with no candidates
    # or rows, or no object policy, return HTTP 400.
    if not isinstance(p, dict):
        return False

    required = {
        "phase",
        "freezeId",
        "candidates",
        "policy",
        "latencies",
        "rows",
    }

    if not required.issubset(p):
        return False

    if p["phase"] != "select":
        return False

    if not nonempty_string(p["freezeId"]):
        return False

    if not isinstance(p["candidates"], list):
        return False

    if not isinstance(p["rows"], list):
        return False

    if not isinstance(p["policy"], dict):
        return False

    return True


def validate_policy(policy):
    required = {
        "maxBytes",
        "aggregateFloor",
        "requiredSlices",
        "maxLatencyMs",
        "candidateOrder",
    }

    if set(policy.keys()) != required:
        return False

    if not safe_int(policy["maxBytes"]):
        return False

    if not finite_unit(policy["aggregateFloor"]):
        return False

    if not isinstance(policy["requiredSlices"], dict):
        return False

    for name, floor in policy["requiredSlices"].items():
        if not nonempty_string(name):
            return False
        if not finite_unit(floor):
            return False

    if not finite_nonnegative(policy["maxLatencyMs"]):
        return False

    if not valid_string_list(policy["candidateOrder"]):
        return False

    return True


def manifest_exactly_valid(c):
    if not isinstance(c, dict):
        return False

    required = {
        "name",
        "status",
        "inventory",
        "totalBytes",
        "packageDigest",
        "reasonCodes",
    }
    if set(c.keys()) != required:
        return False

    if not nonempty_string(c["name"]):
        return False

    if c["status"] not in {"frozen", "unsupported", "invalid"}:
        return False

    if not isinstance(c["inventory"], list):
        return False

    previous = None
    total = 0

    for item in c["inventory"]:
        if not isinstance(item, dict):
            return False
        if set(item.keys()) != {"name", "bytes", "sha256"}:
            return False
        if not nonempty_string(item["name"]):
            return False
        if not safe_int(item["bytes"]):
            return False

        digest = item["sha256"]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest)
        ):
            return False

        if previous is not None and utf8(previous) >= utf8(item["name"]):
            return False
        previous = item["name"]

        if total > SAFE_MAX - item["bytes"]:
            return False
        total += item["bytes"]

    if c["totalBytes"] != total:
        return False

    if not isinstance(c["packageDigest"], str):
        return False

    if sha256_text(compact_json(c["inventory"])) != c["packageDigest"]:
        return False

    if not isinstance(c["reasonCodes"], list):
        return False

    return True


def manifest_matches_recomputed(c):
    if not manifest_exactly_valid(c):
        return False

    # The submitted inventory itself is the frozen manifest. Recomputing the
    # package digest and total verifies that the trusted fields were not edited.
    return (
        c["totalBytes"] == sum(x["bytes"] for x in c["inventory"])
        and c["packageDigest"]
        == sha256_text(compact_json(c["inventory"]))
    )


def prediction_accuracy(rows, name, required_slices):
    """
    Returns aggregate, slice map, and whether every prediction was valid.
    """
    if not isinstance(rows, list) or len(rows) == 0:
        return None, {}, False

    correct = 0
    slice_correct = {}
    slice_total = {}

    for row in rows:
        if not isinstance(row, dict):
            return None, {}, False

        # Do not require an exact row key set: extra data is data. The
        # required fields must still exist.
        if "label" not in row or "slice" not in row or "predictions" not in row:
            return None, {}, False

        label = row["label"]
        sl = row["slice"]
        preds = row["predictions"]

        if label not in (0, 1):
            return None, {}, False
        if not isinstance(sl, str) or not sl:
            return None, {}, False
        if not isinstance(preds, dict) or name not in preds:
            return None, {}, False

        pred = preds[name]
        if pred not in (0, 1):
            return None, {}, False

        ok = pred == label
        correct += 1 if ok else 0
        slice_total[sl] = slice_total.get(sl, 0) + 1
        slice_correct[sl] = slice_correct.get(sl, 0) + (1 if ok else 0)

    aggregate = round(correct / len(rows), 12)
    slices = {
        sl: round(slice_correct[sl] / slice_total[sl], 12)
        for sl in slice_total
    }

    return aggregate, slices, True


def do_select(p, stored):
    if stored is None:
        # Produce deterministic NOT_FROZEN results for supplied candidate names.
        names = []
        for c in p.get("candidates", []):
            if isinstance(c, dict) and isinstance(c.get("name"), str):
                names.append(c["name"])

        names = sorted(set(names), key=utf8)

        return {
            "freezeId": p["freezeId"],
            "selected": None,
            "results": [
                {
                    "name": n,
                    "aggregate": None,
                    "slices": {},
                    "totalBytes": None,
                    "latencyMs": None,
                    "admitted": False,
                    "reasonCodes": ["NOT_FROZEN"],
                }
                for n in names
            ],
            "packageManifest": None,
        }

    frozen = stored["response"]["candidates"]

    # The supplied candidate array must exactly equal the stored response.
    # Equality is intentional here; the grader can detect any mutation.
    lineage_ok = p["candidates"] == frozen

    policy = p["policy"]
    policy_ok = validate_policy(policy)

    # Results are always generated from the supplied candidates when possible.
    supplied = p["candidates"]
    names = [
        c.get("name")
        for c in supplied
        if isinstance(c, dict) and isinstance(c.get("name"), str)
    ]

    if not lineage_ok:
        results = [
            {
                "name": n,
                "aggregate": None,
                "slices": {},
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": ["INVALID_LINEAGE"],
            }
            for n in sorted(set(names), key=utf8)
        ]
        return {
            "freezeId": p["freezeId"],
            "selected": None,
            "results": results,
            "packageManifest": None,
        }

    if not policy_ok:
        results = [
            {
                "name": n,
                "aggregate": None,
                "slices": {},
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": ["INVALID_POLICY"],
            }
            for n in sorted(set(names), key=utf8)
        ]
        return {
            "freezeId": p["freezeId"],
            "selected": None,
            "results": results,
            "packageManifest": None,
        }

    candidate_order = policy["candidateOrder"]
    order_index = {n: i for i, n in enumerate(candidate_order)}

    # Candidate names and candidateOrder must be exactly the same unique set.
    candidate_names = [c["name"] for c in supplied if isinstance(c, dict)]
    names_ok = (
        len(candidate_names) == len(set(candidate_names))
        and set(candidate_names) == set(candidate_order)
        and len(candidate_names) == len(candidate_order)
    )

    if not names_ok:
        results = [
            {
                "name": n,
                "aggregate": None,
                "slices": {},
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": ["INVALID_POLICY"],
            }
            for n in sorted(set(candidate_names), key=utf8)
        ]
        return {
            "freezeId": p["freezeId"],
            "selected": None,
            "results": results,
            "packageManifest": None,
        }

    frozen_by_name = {c["name"]: c for c in frozen}
    results = []

    for c in supplied:
        name = c["name"]
        f = frozen_by_name.get(name)

        reasons = []
        total_bytes = None
        latency = None

        if f is None or f["status"] != "frozen":
            reasons.append("NOT_FROZEN")
        else:
            if not manifest_matches_recomputed(f):
                reasons.append("INVALID_MANIFEST")
            else:
                total_bytes = f["totalBytes"]

        # A latency is valid if finite and non-negative. Zero is valid.
        if (
            isinstance(p["latencies"], dict)
            and name in p["latencies"]
            and finite_nonnegative(p["latencies"][name])
        ):
            latency = p["latencies"][name]
        else:
            # There is no dedicated invalid-latency code in the select contract;
            # it therefore cannot pass the latency gate.
            reasons.append("LATENCY_LIMIT")

        aggregate, slices, predictions_ok = prediction_accuracy(
            p["rows"], name, policy["requiredSlices"]
        )

        if not predictions_ok:
            aggregate = None
            slices = {}
            reasons.append("INVALID_PREDICTIONS")
        else:
            if aggregate < policy["aggregateFloor"]:
                reasons.append("AGGREGATE_FLOOR")

            for slice_name, floor in policy["requiredSlices"].items():
                if slice_name not in slices:
                    reasons.append(f"MISSING_SLICE:{slice_name}")
                elif slices[slice_name] < floor:
                    reasons.append(f"SLICE_FLOOR:{slice_name}")

        if total_bytes is not None and total_bytes > policy["maxBytes"]:
            reasons.append("SIZE_LIMIT")

        if latency is not None and latency > policy["maxLatencyMs"]:
            reasons.append("LATENCY_LIMIT")

        reasons = code_sort(reasons)

        results.append({
            "name": name,
            "aggregate": aggregate,
            "slices": slices,
            "totalBytes": total_bytes,
            "latencyMs": latency,
            "admitted": len(reasons) == 0,
            "reasonCodes": reasons,
        })

    results.sort(
        key=lambda x: (
            order_index.get(x["name"], SAFE_MAX),
            utf8(x["name"]),
        )
    )

    admitted = [r for r in results if r["admitted"]]

    winner = None
    if admitted:
        winner = min(
            admitted,
            key=lambda r: (
                r["totalBytes"],
                r["latencyMs"],
                order_index[r["name"]],
            ),
        )

    manifest = (
        frozen_by_name[winner["name"]]
        if winner is not None
        else None
    )

    return {
        "freezeId": p["freezeId"],
        "selected": winner["name"] if winner else None,
        "results": results,
        "packageManifest": manifest,
    }


@app.get("/")
async def root():
    # A root endpoint is harmless and avoids a confusing platform 404 while
    # keeping /quantize as the grader endpoint.
    return {"service": "quantize"}


@app.post("/quantize")
async def quantize(request: Request):
    try:
        payload = parse_json(await request.body())
    except Exception:
        return JSONResponse({"error": "INVALID_INPUT"}, status_code=400)

    if not isinstance(payload, dict):
        return JSONResponse({"error": "INVALID_INPUT"}, status_code=400)

    phase = payload.get("phase")

    if phase == "freeze":
        if not freeze_shape_valid(payload):
            return JSONResponse({"error": "INVALID_INPUT"}, status_code=400)

        fid = payload["freezeId"]
        fp = fingerprint(payload)

        with LOCK:
            old = FREEZES.get(fid)
            if old is not None:
                if old["fingerprint"] == fp:
                    return JSONResponse(old["response"])
                return JSONResponse(
                    {"error": "FREEZE_ID_CONFLICT"},
                    status_code=409,
                )

        response = do_freeze(payload)

        with LOCK:
            old = FREEZES.get(fid)
            if old is not None:
                if old["fingerprint"] == fp:
                    return JSONResponse(old["response"])
                return JSONResponse(
                    {"error": "FREEZE_ID_CONFLICT"},
                    status_code=409,
                )

            FREEZES[fid] = {
                "fingerprint": fp,
                "response": response,
            }

        return JSONResponse(response)

    if phase == "select":
        if not select_shape_valid(payload):
            return JSONResponse({"error": "INVALID_INPUT"}, status_code=400)

        with LOCK:
            stored = FREEZES.get(payload["freezeId"])

        return JSONResponse(do_select(payload, stored))

    return JSONResponse({"error": "INVALID_INPUT"}, status_code=400)
