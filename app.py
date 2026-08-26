import hashlib
import json
import math
import threading
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

SAFE_MAX = 9007199254740991


def bkey(s: str) -> bytes:
    return s.encode("utf-8")


def compact(v: Any) -> str:
    return json.dumps(
        v,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def strict_json(raw: bytes):
    return json.loads(
        raw.decode("utf-8"),
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
    )


def safe_int(v):
    return (
        isinstance(v, int)
        and not isinstance(v, bool)
        and 0 <= v <= SAFE_MAX
    )


def positive_float(v):
    return (
        isinstance(v, (int, float))
        and not isinstance(v, bool)
        and math.isfinite(v)
        and v >= 0
    )


def finite_01(v):
    return (
        isinstance(v, (int, float))
        and not isinstance(v, bool)
        and math.isfinite(v)
        and 0 <= v <= 1
    )


def nonempty_string(v):
    return isinstance(v, str) and len(v) > 0


def unique_nonempty_strings(v):
    return (
        isinstance(v, list)
        and all(nonempty_string(x) for x in v)
        and len(v) == len(set(v))
    )


def codes_sorted(codes):
    return sorted(set(codes), key=bkey)


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def inventory_for(name, files):
    if not isinstance(files, dict) or not files:
        return None

    inventory = []

    # Every filename must be a non-empty string and every file content must be
    # a UTF-8 string. Duplicate filenames are impossible in a JSON object, but
    # keys are checked explicitly.
    for filename, content in files.items():
        if not nonempty_string(filename) or not isinstance(content, str):
            return None

        data = content.encode("utf-8")
        inventory.append({
            "name": filename,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })

    inventory.sort(key=lambda x: bkey(x["name"]))

    total = 0
    for item in inventory:
        if total > SAFE_MAX - item["bytes"]:
            return None
        total += item["bytes"]

    # Exact key order: name, bytes, sha256.
    package_digest = sha256_text(compact(inventory))

    return inventory, total, package_digest


def freeze_request_valid(payload):
    if not isinstance(payload, dict):
        return False

    required = {
        "phase",
        "freezeId",
        "calibrationDigest",
        "tokenizerDigest",
        "allowedUnsupportedReasons",
        "candidates",
    }

    if not required.issubset(payload.keys()):
        return False

    if payload["phase"] != "freeze":
        return False

    if (
        not nonempty_string(payload["freezeId"])
        or len(payload["freezeId"]) > 128
    ):
        return False

    if not nonempty_string(payload["calibrationDigest"]):
        return False

    if not nonempty_string(payload["tokenizerDigest"]):
        return False

    if not unique_nonempty_strings(payload["allowedUnsupportedReasons"]):
        return False

    candidates = payload["candidates"]

    if not isinstance(candidates, list) or not candidates:
        return False

    names = []

    for c in candidates:
        if not isinstance(c, dict):
            return False

        required_candidate = {
            "name",
            "files",
            "loadable",
            "calibrationDigest",
            "tokenizerDigest",
            "unsupportedReason",
        }

        if not required_candidate.issubset(c.keys()):
            return False

        if not nonempty_string(c["name"]):
            return False

        names.append(c["name"])

        if not isinstance(c["loadable"], bool):
            return False

        if not nonempty_string(c["calibrationDigest"]):
            return False

        if not nonempty_string(c["tokenizerDigest"]):
            return False

        if (
            "unsupportedReason" in c
            and c["unsupportedReason"] is not None
            and not nonempty_string(c["unsupportedReason"])
        ):
            return False

        if not isinstance(c["files"], dict) or not c["files"]:
            return False

        for filename, content in c["files"].items():
            if not nonempty_string(filename):
                return False
            if not isinstance(content, str):
                return False

    return len(names) == len(set(names))


def build_freeze(payload):
    result = []

    allowed = set(payload["allowedUnsupportedReasons"])

    for candidate in payload["candidates"]:
        name = candidate["name"]

        inv = inventory_for(name, candidate["files"])

        if inv is None:
            result.append({
                "name": name,
                "status": "invalid",
                "inventory": [],
                "totalBytes": None,
                "packageDigest": None,
                "reasonCodes": ["INVALID_INPUT"],
            })
            continue

        inventory, total_bytes, package_digest = inv
        reasons = []

        unsupported = candidate.get("unsupportedReason")

        if unsupported is not None:
            if unsupported not in allowed:
                reasons.append("UNALLOWED_UNSUPPORTED_REASON")
            else:
                status = "unsupported"

                # An allowed unsupported reason is sufficient to classify it
                # unsupported. Other integrity failures still make it invalid.
                if candidate["calibrationDigest"] != payload["calibrationDigest"]:
                    reasons.append("CALIBRATION_MISMATCH")

                if candidate["tokenizerDigest"] != payload["tokenizerDigest"]:
                    reasons.append("TOKENIZER_MISMATCH")

                if reasons:
                    status = "invalid"

                result.append({
                    "name": name,
                    "status": status,
                    "inventory": inventory,
                    "totalBytes": total_bytes,
                    "packageDigest": package_digest,
                    "reasonCodes": codes_sorted(reasons),
                })
                continue

        if not candidate["loadable"]:
            reasons.append("NOT_LOADABLE")

        if candidate["calibrationDigest"] != payload["calibrationDigest"]:
            reasons.append("CALIBRATION_MISMATCH")

        if candidate["tokenizerDigest"] != payload["tokenizerDigest"]:
            reasons.append("TOKENIZER_MISMATCH")

        status = "frozen" if not reasons else "invalid"

        result.append({
            "name": name,
            "status": status,
            "inventory": inventory,
            "totalBytes": total_bytes,
            "packageDigest": package_digest,
            "reasonCodes": codes_sorted(reasons),
        })

    result.sort(key=lambda x: bkey(x["name"]))

    return {
        "freezeId": payload["freezeId"],
        "candidates": result,
    }


def select_request_valid(payload):
    if not isinstance(payload, dict):
        return False

    required = {
        "phase",
        "freezeId",
        "candidates",
        "policy",
        "latencies",
        "rows",
    }

    if not required.issubset(payload.keys()):
        return False

    if payload["phase"] != "select":
        return False

    if not nonempty_string(payload["freezeId"]):
        return False

    if not isinstance(payload["candidates"], list):
        return False

    if not isinstance(payload["rows"], list):
        return False

    if not isinstance(payload["policy"], dict):
        return False

    if not isinstance(payload["latencies"], dict):
        return False

    return True


def manifest_valid(c):
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

    inventory = c["inventory"]

    if not isinstance(inventory, list):
        return False

    previous = None
    total = 0

    for item in inventory:
        if not isinstance(item, dict):
            return False
        if set(item.keys()) != {"name", "bytes", "sha256"}:
            return False
        if not nonempty_string(item["name"]):
            return False
        if not safe_int(item["bytes"]):
            return False
        if (
            not isinstance(item["sha256"], str)
            or len(item["sha256"]) != 64
            or any(ch not in "0123456789abcdef" for ch in item["sha256"])
        ):
            return False

        if previous is not None and bkey(previous) >= bkey(item["name"]):
            return False

        previous = item["name"]

        if total > SAFE_MAX - item["bytes"]:
            return False
        total += item["bytes"]

    if c["totalBytes"] != total:
        return False

    expected_digest = sha256_text(compact(inventory))
    if c["packageDigest"] != expected_digest:
        return False

    if not isinstance(c["reasonCodes"], list):
        return False

    return True


def recompute_manifest(c):
    if not manifest_valid(c):
        return False

    # Recompute package digest from the exact recorded inventory and total.
    inventory = c["inventory"]
    total = sum(x["bytes"] for x in inventory)

    return (
        total == c["totalBytes"]
        and sha256_text(compact(inventory)) == c["packageDigest"]
    )


def select(payload, stored):
    candidate_results = []

    if stored is None:
        # No frozen state exists.
        names = []
        if isinstance(payload.get("candidates"), list):
            for c in payload["candidates"]:
                if isinstance(c, dict) and isinstance(c.get("name"), str):
                    names.append(c["name"])

        return {
            "freezeId": payload["freezeId"],
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
                for n in sorted(set(names), key=bkey)
            ],
            "packageManifest": None,
        }

    frozen_response = stored["response"]

    # Exact candidate array equality is required.
    if payload["candidates"] != frozen_response["candidates"]:
        names = []
        for c in payload["candidates"]:
            if isinstance(c, dict) and isinstance(c.get("name"), str):
                names.append(c["name"])

        return {
            "freezeId": payload["freezeId"],
            "selected": None,
            "results": [
                {
                    "name": n,
                    "aggregate": None,
                    "slices": {},
                    "totalBytes": None,
                    "latencyMs": None,
                    "admitted": False,
                    "reasonCodes": ["INVALID_LINEAGE"],
                }
                for n in sorted(set(names), key=bkey)
            ],
            "packageManifest": None,
        }

    candidates = payload["candidates"]
    policy = payload["policy"]
    latencies = payload["latencies"]
    rows = payload["rows"]

    if (
        not isinstance(policy, dict)
        or set(policy.keys())
        != {
            "maxBytes",
            "aggregateFloor",
            "requiredSlices",
            "maxLatencyMs",
            "candidateOrder",
        }
        or not safe_int(policy["maxBytes"])
        or not finite_01(policy["aggregateFloor"])
        or not isinstance(policy["requiredSlices"], dict)
        or not positive_float(policy["maxLatencyMs"])
        or not unique_nonempty_strings(policy["candidateOrder"])
        or len(policy["candidateOrder"]) != len(candidates)
    ):
        return {
            "freezeId": payload["freezeId"],
            "selected": None,
            "results": [],
            "packageManifest": None,
        }

    names = []
    for c in candidates:
        if isinstance(c, dict) and isinstance(c.get("name"), str):
            names.append(c["name"])

    names_unique = (
        len(names) == len(set(names))
        and set(names) == set(policy["candidateOrder"])
    )

    if not names_unique:
        # INVALID_POLICY for every candidate because candidateOrder cannot
        # establish the required deterministic ranking.
        for c in candidates:
            name = c.get("name") if isinstance(c, dict) else ""
            if isinstance(name, str):
                candidate_results.append({
                    "name": name,
                    "aggregate": None,
                    "slices": {},
                    "totalBytes": None,
                    "latencyMs": None,
                    "admitted": False,
                    "reasonCodes": ["INVALID_POLICY"],
                })

        candidate_results.sort(
            key=lambda x: bkey(x["name"])
        )

        return {
            "freezeId": payload["freezeId"],
            "selected": None,
            "results": candidate_results,
            "packageManifest": None,
        }

    order_index = {
        name: i for i, name in enumerate(policy["candidateOrder"])
    }

    required_slices = policy["requiredSlices"]

    for candidate in candidates:
        name = candidate["name"]
        reasons = []
        aggregate = None
        slices_result = {}
        total_bytes = None
        latency = None

        frozen = next(
            (
                x for x in frozen_response["candidates"]
                if x["name"] == name
            ),
            None,
        )

        if frozen is None:
            reasons.append("NOT_FROZEN")
        else:
            if frozen["status"] != "frozen":
                reasons.append("NOT_FROZEN")

            if not recompute_manifest(frozen):
                reasons.append("INVALID_MANIFEST")
            else:
                total_bytes = frozen["totalBytes"]

        if name not in latencies or not positive_float(latencies.get(name)):
            latency = None
            reasons.append("INVALID_MANIFEST")
        else:
            latency = latencies[name]

        if isinstance(rows, list) and rows:
            prediction_valid = True
            correct = 0
            slice_values = {}

            for row in rows:
                if (
                    not isinstance(row, dict)
                    or set(row.keys()) != {
                        "label",
                        "slice",
                        "predictions",
                    }
                    or row["label"] not in (0, 1)
                    or not isinstance(row["slice"], str)
                    or not row["slice"]
                    or not isinstance(row["predictions"], dict)
                    or name not in row["predictions"]
                    or row["predictions"][name] not in (0, 1)
                ):
                    prediction_valid = False
                    break

                pred = row["predictions"][name]
                ok = pred == row["label"]
                correct += int(ok)
                slice_values.setdefault(row["slice"], []).append(ok)

            if not prediction_valid:
                reasons.append("INVALID_PREDICTIONS")
                aggregate = None
                slices_result = {}
            else:
                aggregate = round(correct / len(rows), 12)

                for slice_name, values in slice_values.items():
                    slices_result[slice_name] = round(
                        sum(values) / len(values),
                        12,
                    )

                if aggregate < policy["aggregateFloor"]:
                    reasons.append("AGGREGATE_FLOOR")

                for slice_name, floor in required_slices.items():
                    if slice_name not in slices_result:
                        reasons.append(
                            f"MISSING_SLICE:{slice_name}"
                        )
                    elif slices_result[slice_name] < floor:
                        reasons.append(
                            f"SLICE_FLOOR:{slice_name}"
                        )
        else:
            reasons.append("INVALID_PREDICTIONS")
            aggregate = None
            slices_result = {}

        if total_bytes is not None and total_bytes > policy["maxBytes"]:
            reasons.append("SIZE_LIMIT")

        if latency is not None and latency > policy["maxLatencyMs"]:
            reasons.append("LATENCY_LIMIT")

        reasons = codes_sorted(reasons)

        admitted = not reasons

        candidate_results.append({
            "name": name,
            "aggregate": aggregate,
            "slices": slices_result,
            "totalBytes": total_bytes,
            "latencyMs": latency,
            "admitted": admitted,
            "reasonCodes": reasons,
        })

    candidate_results.sort(
        key=lambda x: (
            order_index.get(x["name"], SAFE_MAX),
            bkey(x["name"]),
        )
    )

    admitted = [
        x for x in candidate_results
        if x["admitted"]
    ]

    winner = None

    if admitted:
        winner = min(
            admitted,
            key=lambda x: (
                x["totalBytes"],
                x["latencyMs"],
                order_index[x["name"]],
            ),
        )

    manifest = None

    if winner is not None:
        manifest = next(
            x for x in frozen_response["candidates"]
            if x["name"] == winner["name"]
        )

    return {
        "freezeId": payload["freezeId"],
        "selected": winner["name"] if winner else None,
        "results": candidate_results,
        "packageManifest": manifest,
    }


FREEZES = {}
LOCK = threading.Lock()


def request_fingerprint(payload):
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


@app.post("/quantize")
async def quantize(request: Request):
    try:
        payload = strict_json(await request.body())
    except Exception:
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400,
        )

    if not isinstance(payload, dict):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400,
        )

    phase = payload.get("phase")

    if phase == "freeze":
        if not freeze_request_valid(payload):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        fp = request_fingerprint(payload)
        freeze_id = payload["freezeId"]

        with LOCK:
            old = FREEZES.get(freeze_id)
            if old is not None:
                if old["fingerprint"] == fp:
                    return JSONResponse(old["response"])
                return JSONResponse(
                    {"error": "FREEZE_ID_CONFLICT"},
                    status_code=409,
                )

        response = build_freeze(payload)

        with LOCK:
            # Identical concurrent replay remains deterministic.
            old = FREEZES.get(freeze_id)
            if old is not None:
                if old["fingerprint"] == fp:
                    return JSONResponse(old["response"])
                return JSONResponse(
                    {"error": "FREEZE_ID_CONFLICT"},
                    status_code=409,
                )

            FREEZES[freeze_id] = {
                "fingerprint": fp,
                "response": response,
            }

        return JSONResponse(response)

    if phase == "select":
        # Explicit HTTP-400 contract for missing/wrong top-level arrays/policy.
        if (
            "freezeId" not in payload
            or "candidates" not in payload
            or "rows" not in payload
            or "policy" not in payload
            or not isinstance(payload["candidates"], list)
            or not isinstance(payload["rows"], list)
            or not isinstance(payload["policy"], dict)
        ):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        if len(payload["candidates"]) == 0:
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        freeze_id = payload["freezeId"]

        with LOCK:
            stored = FREEZES.get(freeze_id)

        return JSONResponse(select(payload, stored))

    return JSONResponse(
        {"error": "INVALID_INPUT"},
        status_code=400,
    )
