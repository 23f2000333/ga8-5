import copy
import hashlib
import json
import math

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

SAFE_INT_MAX = 9007199254740991

# freezeId -> persisted freeze state
FREEZES = {}


# ============================================================
# HELPERS
# ============================================================

def compact_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=False,
    )


def canonical_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def sha256_utf8(value):
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def utf8_sort_key(value):
    return value.encode("utf-8")


def nonempty_string(value):
    return isinstance(value, str) and len(value) > 0


def safe_nonnegative_int(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= SAFE_INT_MAX
    )


def safe_positive_int(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 < value <= SAFE_INT_MAX
    )


def finite_nonnegative(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= 0
    )


def finite_unit(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and 0 <= value <= 1
    )


def unique_nonempty_strings(value):
    if not isinstance(value, list):
        return False

    seen = set()

    for item in value:
        if not nonempty_string(item):
            return False

        if item in seen:
            return False

        seen.add(item)

    return True


def sorted_codes(codes):
    return sorted(
        set(codes),
        key=utf8_sort_key,
    )


def is_binary_prediction(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value in (0, 1)
    )


# ============================================================
# INVENTORY
# ============================================================

def build_inventory(files):
    """
    Returns:
        valid,
        inventory,
        totalBytes,
        packageDigest
    """

    if not isinstance(files, dict):
        return False, [], None, None

    if len(files) == 0:
        return False, [], None, None

    inventory = []

    try:
        names = sorted(
            files.keys(),
            key=utf8_sort_key,
        )
    except Exception:
        return False, [], None, None

    for name in names:

        if not nonempty_string(name):
            return False, [], None, None

        content = files[name]

        if not isinstance(content, str):
            return False, [], None, None

        raw = content.encode("utf-8")

        inventory.append({
            "name": name,
            "bytes": len(raw),
            "sha256": hashlib.sha256(
                raw
            ).hexdigest(),
        })

    total_bytes = sum(
        item["bytes"]
        for item in inventory
    )

    package_digest = sha256_utf8(
        compact_json(inventory)
    )

    return (
        True,
        inventory,
        total_bytes,
        package_digest,
    )


# ============================================================
# FREEZE VALIDATION
# ============================================================

def validate_freeze_request(body):
    if not isinstance(body, dict):
        return False

    if body.get("phase") != "freeze":
        return False

    freeze_id = body.get("freezeId")

    if (
        not nonempty_string(freeze_id)
        or len(freeze_id) > 128
    ):
        return False

    if not nonempty_string(
        body.get("calibrationDigest")
    ):
        return False

    if not nonempty_string(
        body.get("tokenizerDigest")
    ):
        return False

    if not unique_nonempty_strings(
        body.get(
            "allowedUnsupportedReasons"
        )
    ):
        return False

    candidates = body.get("candidates")

    if (
        not isinstance(candidates, list)
        or len(candidates) == 0
    ):
        return False

    names = []

    for candidate in candidates:

        if not isinstance(candidate, dict):
            return False

        name = candidate.get("name")

        if not nonempty_string(name):
            return False

        names.append(name)

    if len(names) != len(set(names)):
        return False

    return True


# ============================================================
# FREEZE CANDIDATE
# ============================================================

def freeze_one_candidate(
    candidate,
    request_calibration,
    request_tokenizer,
    allowed_reasons,
):
    name = candidate["name"]

    files = candidate.get("files")

    files_valid, inventory, total_bytes, package_digest = (
        build_inventory(files)
    )

    # --------------------------------------------------------
    # Invalid files
    # --------------------------------------------------------

    if not files_valid:
        return {
            "name": name,
            "status": "invalid",
            "inventory": [],
            "totalBytes": None,
            "packageDigest": None,
            "reasonCodes": [],
        }

    codes = set()

    unsupported_reason = candidate.get(
        "unsupportedReason"
    )

    # --------------------------------------------------------
    # Unsupported candidate
    # --------------------------------------------------------

    if (
        isinstance(unsupported_reason, str)
        and unsupported_reason != ""
    ):

        if unsupported_reason in allowed_reasons:

            return {
                "name": name,
                "status": "unsupported",
                "inventory": inventory,
                "totalBytes": total_bytes,
                "packageDigest": package_digest,
                "reasonCodes": [],
            }

        codes.add(
            "UNALLOWED_UNSUPPORTED_REASON"
        )

        return {
            "name": name,
            "status": "invalid",
            "inventory": inventory,
            "totalBytes": total_bytes,
            "packageDigest": package_digest,
            "reasonCodes": sorted_codes(codes),
        }

    # --------------------------------------------------------
    # Normal candidate
    # --------------------------------------------------------

    if candidate.get("loadable") is not True:
        codes.add("NOT_LOADABLE")

    if candidate.get(
        "calibrationDigest"
    ) != request_calibration:
        codes.add("CALIBRATION_MISMATCH")

    if candidate.get(
        "tokenizerDigest"
    ) != request_tokenizer:
        codes.add("TOKENIZER_MISMATCH")

    if codes:

        return {
            "name": name,
            "status": "invalid",
            "inventory": inventory,
            "totalBytes": total_bytes,
            "packageDigest": package_digest,
            "reasonCodes": sorted_codes(codes),
        }

    return {
        "name": name,
        "status": "frozen",
        "inventory": inventory,
        "totalBytes": total_bytes,
        "packageDigest": package_digest,
        "reasonCodes": [],
    }


# ============================================================
# FREEZE
# ============================================================

def handle_freeze(body):

    freeze_id = body["freezeId"]

    # --------------------------------------------------------
    # Existing freeze
    # --------------------------------------------------------

    request_signature = canonical_json(body)

    if freeze_id in FREEZES:

        previous = FREEZES[freeze_id]

        if (
            previous["request"]
            == request_signature
        ):

            return (
                200,
                copy.deepcopy(
                    previous["response"]
                ),
            )

        return (
            409,
            {
                "error":
                    "FREEZE_ID_CONFLICT"
            },
        )

    # --------------------------------------------------------
    # Build response
    # --------------------------------------------------------

    allowed = set(
        body["allowedUnsupportedReasons"]
    )

    candidates = []

    for candidate in body["candidates"]:

        result = freeze_one_candidate(
            candidate,
            body["calibrationDigest"],
            body["tokenizerDigest"],
            allowed,
        )

        candidates.append(result)

    # Required ordering: UTF-8 candidate name.
    candidates.sort(
        key=lambda item:
            item["name"].encode("utf-8")
    )

    response = {
        "freezeId": freeze_id,
        "candidates": candidates,
    }

    # --------------------------------------------------------
    # Persist complete response.
    # --------------------------------------------------------

    FREEZES[freeze_id] = {
        "request": request_signature,
        "response": copy.deepcopy(
            response
        ),
    }

    return 200, response


# ============================================================
# SELECT REQUEST VALIDATION
# ============================================================

def validate_select_request(body):

    if not isinstance(body, dict):
        return False

    if body.get("phase") != "select":
        return False

    if not nonempty_string(
        body.get("freezeId")
    ):
        return False

    # Explicitly required to be arrays.
    if not isinstance(
        body.get("candidates"),
        list,
    ):
        return False

    if not isinstance(
        body.get("rows"),
        list,
    ):
        return False

    # Explicitly required to be an object.
    if not isinstance(
        body.get("policy"),
        dict,
    ):
        return False

    # IMPORTANT:
    # latencies is intentionally NOT required here.
    # Invalid/missing latency becomes null at candidate level.

    return True


# ============================================================
# POLICY
# ============================================================

def validate_policy(policy):

    required = {
        "maxBytes",
        "aggregateFloor",
        "requiredSlices",
        "maxLatencyMs",
        "candidateOrder",
    }

    if not required.issubset(
        policy.keys()
    ):
        return False

    if not safe_nonnegative_int(
        policy["maxBytes"]
    ):
        return False

    if not finite_unit(
        policy["aggregateFloor"]
    ):
        return False

    required_slices = policy[
        "requiredSlices"
    ]

    if not isinstance(
        required_slices,
        dict,
    ):
        return False

    for name, floor in required_slices.items():

        if not nonempty_string(name):
            return False

        if not finite_unit(floor):
            return False

    if not finite_nonnegative(
        policy["maxLatencyMs"]
    ):
        return False

    if not unique_nonempty_strings(
        policy["candidateOrder"]
    ):
        return False

    return True


# ============================================================
# RECOMPUTE SUBMITTED MANIFEST
# ============================================================

def recompute_manifest(candidate):

    if not isinstance(candidate, dict):
        return None

    name = candidate.get("name")

    if not nonempty_string(name):
        return None

    inventory = candidate.get(
        "inventory"
    )

    if not isinstance(
        inventory,
        list,
    ):
        return None

    names = []

    for entry in inventory:

        if not isinstance(entry, dict):
            return None

        # Exact key order.
        if list(entry.keys()) != [
            "name",
            "bytes",
            "sha256",
        ]:
            return None

        entry_name = entry["name"]

        if not nonempty_string(
            entry_name
        ):
            return None

        if not safe_nonnegative_int(
            entry["bytes"]
        ):
            return None

        digest = entry["sha256"]

        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or digest != digest.lower()
        ):
            return None

        names.append(entry_name)

    # Sorted by UTF-8 filename.
    if names != sorted(
        names,
        key=utf8_sort_key,
    ):
        return None

    # Unique filenames.
    if len(names) != len(set(names)):
        return None

    total_bytes = sum(
        entry["bytes"]
        for entry in inventory
    )

    package_digest = sha256_utf8(
        compact_json(inventory)
    )

    return {
        "inventory": inventory,
        "totalBytes": total_bytes,
        "packageDigest": package_digest,
    }


# ============================================================
# METRICS
# ============================================================

def compute_metrics(
    candidate_name,
    rows,
    required_slices,
):
    """
    Invalid predictions produce:
        aggregate = null
        required slices = null
    """

    slice_correct = {
        name: 0
        for name in required_slices
    }

    slice_total = {
        name: 0
        for name in required_slices
    }

    total_correct = 0

    if len(rows) == 0:
        return (
            False,
            None,
            {
                name: None
                for name in required_slices
            },
        )

    for row in rows:

        if not isinstance(row, dict):
            return (
                False,
                None,
                {
                    name: None
                    for name in required_slices
                },
            )

        if "label" not in row:
            return (
                False,
                None,
                {
                    name: None
                    for name in required_slices
                },
            )

        if "slice" not in row:
            return (
                False,
                None,
                {
                    name: None
                    for name in required_slices
                },
            )

        predictions = row.get(
            "predictions"
        )

        if not isinstance(
            predictions,
            dict,
        ):
            return (
                False,
                None,
                {
                    name: None
                    for name in required_slices
                },
            )

        if candidate_name not in predictions:
            return (
                False,
                None,
                {
                    name: None
                    for name in required_slices
                },
            )

        prediction = predictions[
            candidate_name
        ]

        if not is_binary_prediction(
            prediction
        ):
            return (
                False,
                None,
                {
                    name: None
                    for name in required_slices
                },
            )

        correct = (
            prediction == row["label"]
        )

        if correct:
            total_correct += 1

        slice_name = row["slice"]

        if slice_name in slice_total:

            slice_total[
                slice_name
            ] += 1

            if correct:
                slice_correct[
                    slice_name
                ] += 1

    aggregate = round(
        total_correct / len(rows),
        12,
    )

    slices = {}

    for name in required_slices:

        if slice_total[name] == 0:
            slices[name] = None
        else:
            slices[name] = round(
                slice_correct[name]
                / slice_total[name],
                12,
            )

    return (
        True,
        aggregate,
        slices,
    )


# ============================================================
# LATENCY
# ============================================================

def get_latency(
    latencies,
    name,
):
    """
    Missing/malformed latency is not request-level INVALID_INPUT.
    """

    if not isinstance(
        latencies,
        dict,
    ):
        return None

    value = latencies.get(name)

    if not finite_nonnegative(value):
        return None

    return value


# ============================================================
# SELECT ONE CANDIDATE
# ============================================================

def evaluate_candidate(
    stored_candidate,
    submitted_candidate,
    rows,
    policy,
    latencies,
):
    name = stored_candidate["name"]

    codes = set()

    # --------------------------------------------------------
    # Frozen status
    # --------------------------------------------------------

    if stored_candidate["status"] != "frozen":
        codes.add("NOT_FROZEN")

    # --------------------------------------------------------
    # Exact submitted candidate / lineage
    # --------------------------------------------------------

    if (
        canonical_json(
            submitted_candidate
        )
        != canonical_json(
            stored_candidate
        )
    ):
        codes.add("INVALID_LINEAGE")

    # --------------------------------------------------------
    # Recompute manifest
    # --------------------------------------------------------

    recomputed = recompute_manifest(
        submitted_candidate
    )

    total_bytes = None

    if recomputed is None:

        codes.add(
            "INVALID_MANIFEST"
        )

    else:

        total_bytes = recomputed[
            "totalBytes"
        ]

        # IMPORTANT:
        # Never trust submitted totalBytes.
        #
        # Only inventory/packageDigest are compared
        # with the frozen manifest.
        if (
            recomputed["inventory"]
            != stored_candidate[
                "inventory"
            ]
            or
            recomputed["packageDigest"]
            != stored_candidate[
                "packageDigest"
            ]
        ):
            codes.add(
                "INVALID_MANIFEST"
            )

    # --------------------------------------------------------
    # Latency
    # --------------------------------------------------------

    latency = get_latency(
        latencies,
        name,
    )

    if latency is None:
        codes.add(
            "LATENCY_LIMIT"
        )

    # --------------------------------------------------------
    # Predictions
    # --------------------------------------------------------

    (
        predictions_valid,
        aggregate,
        slices,
    ) = compute_metrics(
        name,
        rows,
        policy["requiredSlices"],
    )

    if not predictions_valid:

        codes.add(
            "INVALID_PREDICTIONS"
        )

        aggregate = None

        slices = {
            name: None
            for name in policy[
                "requiredSlices"
            ]
        }

    # --------------------------------------------------------
    # Aggregate
    # --------------------------------------------------------

    if aggregate is not None:

        if (
            aggregate
            < policy["aggregateFloor"]
        ):
            codes.add(
                "AGGREGATE_FLOOR"
            )

    # --------------------------------------------------------
    # Required slices
    # --------------------------------------------------------

    for (
        slice_name,
        floor,
    ) in policy[
        "requiredSlices"
    ].items():

        value = slices.get(
            slice_name
        )

        if value is None:

            codes.add(
                f"MISSING_SLICE:{slice_name}"
            )

        elif value < floor:

            codes.add(
                f"SLICE_FLOOR:{slice_name}"
            )

    # --------------------------------------------------------
    # Size
    # --------------------------------------------------------

    if (
        total_bytes is not None
        and total_bytes
        > policy["maxBytes"]
    ):
        codes.add(
            "SIZE_LIMIT"
        )

    # --------------------------------------------------------
    # Latency ceiling
    # --------------------------------------------------------

    if (
        latency is not None
        and latency
        > policy["maxLatencyMs"]
    ):
        codes.add(
            "LATENCY_LIMIT"
        )

    return {
        "name": name,
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": total_bytes,
        "latencyMs": latency,
        "admitted": len(codes) == 0,
        "reasonCodes": sorted_codes(codes),
    }


# ============================================================
# SELECT
# ============================================================

def handle_select(body):

    freeze_id = body["freezeId"]

    # --------------------------------------------------------
    # Unknown freeze
    # --------------------------------------------------------

    if freeze_id not in FREEZES:

        policy = body.get(
            "policy",
            {},
        )

        required_slices = {}

        if isinstance(
            policy,
            dict,
        ) and isinstance(
            policy.get(
                "requiredSlices"
            ),
            dict,
        ):
            required_slices = policy[
                "requiredSlices"
            ]

        names = []

        for candidate in body[
            "candidates"
        ]:

            if (
                isinstance(
                    candidate,
                    dict,
                )
                and nonempty_string(
                    candidate.get("name")
                )
            ):
                names.append(
                    candidate["name"]
                )

        names = sorted(
            set(names),
            key=utf8_sort_key,
        )

        results = []

        for name in names:

            results.append({
                "name": name,
                "aggregate": None,
                "slices": {
                    key: None
                    for key in required_slices
                },
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": [
                    "NOT_FROZEN"
                ],
            })

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None,
        }

    stored_response = FREEZES[
        freeze_id
    ]["response"]

    stored_candidates = (
        stored_response["candidates"]
    )

    stored_by_name = {
        candidate["name"]: candidate
        for candidate in stored_candidates
    }

    # --------------------------------------------------------
    # Policy
    # --------------------------------------------------------

    policy = body["policy"]

    if not validate_policy(
        policy
    ):

        results = []

        for candidate in body[
            "candidates"
        ]:

            if not isinstance(
                candidate,
                dict,
            ):
                continue

            name = candidate.get(
                "name",
                "",
            )

            results.append({
                "name": name,
                "aggregate": None,
                "slices": {},
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": [
                    "INVALID_POLICY"
                ],
            })

        results.sort(
            key=lambda x:
                x["name"].encode("utf-8")
        )

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None,
        }

    # --------------------------------------------------------
    # Candidate array must exactly equal persisted response.
    # --------------------------------------------------------

    submitted_candidates = body[
        "candidates"
    ]

    if (
        canonical_json(
            submitted_candidates
        )
        != canonical_json(
            stored_candidates
        )
    ):

        names = []

        for candidate in submitted_candidates:

            if (
                isinstance(
                    candidate,
                    dict,
                )
                and nonempty_string(
                    candidate.get("name")
                )
            ):
                names.append(
                    candidate["name"]
                )

        names = sorted(
            set(names),
            key=utf8_sort_key,
        )

        results = []

        for name in names:

            results.append({
                "name": name,
                "aggregate": None,
                "slices": {
                    key: None
                    for key in policy[
                        "requiredSlices"
                    ]
                },
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": [
                    "INVALID_LINEAGE"
                ],
            })

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None,
        }

    # --------------------------------------------------------
    # Candidate name set / candidateOrder
    # --------------------------------------------------------

    candidate_names = [
        candidate["name"]
        for candidate in submitted_candidates
    ]

    candidate_set = set(
        candidate_names
    )

    order = policy[
        "candidateOrder"
    ]

    if (
        set(order) != candidate_set
        or len(order) != len(candidate_set)
    ):

        results = []

        for name in sorted(
            candidate_set,
            key=utf8_sort_key,
        ):

            results.append({
                "name": name,
                "aggregate": None,
                "slices": {
                    key: None
                    for key in policy[
                        "requiredSlices"
                    ]
                },
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": [
                    "INVALID_POLICY"
                ],
            })

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None,
        }

    submitted_by_name = {
        candidate["name"]: candidate
        for candidate in submitted_candidates
    }

    # --------------------------------------------------------
    # Evaluate all candidates
    # --------------------------------------------------------

    results_by_name = {}

    latencies = body.get(
        "latencies"
    )

    for name in candidate_set:

        results_by_name[name] = (
            evaluate_candidate(
                stored_by_name[name],
                submitted_by_name[name],
                body["rows"],
                policy,
                latencies,
            )
        )

    # --------------------------------------------------------
    # Result ordering:
    # candidateOrder first,
    # UTF-8 name fallback.
    # --------------------------------------------------------

    order_index = {
        name: index
        for index, name
        in enumerate(order)
    }

    results = sorted(
        results_by_name.values(),
        key=lambda result: (
            order_index.get(
                result["name"],
                len(order),
            ),
            result["name"].encode("utf-8"),
        ),
    )

    # --------------------------------------------------------
    # Winner
    #
    # smaller bytes
    # lower latency
    # candidateOrder
    # --------------------------------------------------------

    admitted = [
        result
        for result in results
        if result["admitted"]
    ]

    admitted.sort(
        key=lambda result: (
            result["totalBytes"],
            result["latencyMs"],
            order_index[
                result["name"]
            ],
        )
    )

    selected = None
    package_manifest = None

    if admitted:

        winner = admitted[0]

        selected = winner["name"]

        package_manifest = copy.deepcopy(
            stored_by_name[selected]
        )

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest,
    }


# ============================================================
# HTTP ENDPOINT
# ============================================================

@app.post("/quantize")
async def quantize(request: Request):

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            },
        )

    if not isinstance(body, dict):
        return JSONResponse(
            status_code=400,
            content={
                "error": "INVALID_INPUT"
            },
        )

    phase = body.get("phase")

    # ========================================================
    # FREEZE
    # ========================================================

    if phase == "freeze":

        if not validate_freeze_request(
            body
        ):
            return JSONResponse(
                status_code=400,
                content={
                    "error": "INVALID_INPUT"
                },
            )

        status, response = handle_freeze(
            body
        )

        return JSONResponse(
            status_code=status,
            content=response,
        )

    # ========================================================
    # SELECT
    # ========================================================

    if phase == "select":

        if not validate_select_request(
            body
        ):
            return JSONResponse(
                status_code=400,
                content={
                    "error": "INVALID_INPUT"
                },
            )

        response = handle_select(
            body
        )

        return JSONResponse(
            status_code=200,
            content=response,
        )

    # ========================================================
    # UNKNOWN / MISSING PHASE
    # ========================================================

    return JSONResponse(
        status_code=400,
        content={
            "error": "INVALID_INPUT"
        },
    )


@app.get("/")
async def root():
    return {
        "status": "ok"
    }
