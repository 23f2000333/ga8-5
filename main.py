import copy
import hashlib
import json
import math

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# ============================================================
# GLOBAL STATE
# ============================================================

# freezeId -> {
#     "request": canonical freeze request,
#     "response": exact response returned,
#     "internal": internal candidate information
# }
FREEZES = {}

SAFE_INT_MAX = 9007199254740991


# ============================================================
# BASIC HELPERS
# ============================================================

def compact_json(value):
    """
    Compact JSON.

    sort_keys=False is intentional:
    insertion order is preserved.

    This matters for inventory:
        name, bytes, sha256
    """

    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=False,
    )


def canonical_json(value):
    """
    Used when comparing arbitrary request objects.

    Object key order should not make two otherwise identical
    requests different.
    """

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


def sha256_json(value):
    return sha256_utf8(
        compact_json(value)
    )


def utf8_bytes(value):
    return value.encode("utf-8")


def safe_nonnegative_int(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= SAFE_INT_MAX
    )


def nonempty_string(value):
    return (
        isinstance(value, str)
        and len(value) > 0
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


def utf8_sort_key(value):
    return value.encode("utf-8")


def add_code(codes, code):
    codes.add(code)


def sorted_codes(codes):
    return sorted(
        codes,
        key=utf8_sort_key,
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


# ============================================================
# FILE INVENTORY
# ============================================================

def build_inventory(files):
    """
    Returns:
        valid, inventory, totalBytes, packageDigest

    Inventory entries are created in UTF-8 filename order.
    """

    if not isinstance(files, dict) or not files:
        return False, [], None, None

    inventory = []

    for filename in sorted(
        files.keys(),
        key=utf8_sort_key,
    ):

        # Filename itself must be a non-empty string.
        if not nonempty_string(filename):
            return False, [], None, None

        content = files[filename]

        # Every file must be a UTF-8 string.
        if not isinstance(content, str):
            return False, [], None, None

        raw = utf8_bytes(content)

        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })

    total_bytes = sum(
        entry["bytes"]
        for entry in inventory
    )

    # Exact compact JSON of the inventory.
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
# FREEZE REQUEST VALIDATION
# ============================================================

def validate_freeze_top_level(body):
    """
    Only structural request errors become HTTP 400.
    """

    if not isinstance(body, dict):
        return False

    if body.get("phase") != "freeze":
        return False

    if not nonempty_string(
        body.get("freezeId")
    ):
        return False

    if len(body["freezeId"]) > 128:
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
        body.get("allowedUnsupportedReasons")
    ):
        return False

    candidates = body.get("candidates")

    if (
        not isinstance(candidates, list)
        or len(candidates) == 0
    ):
        return False

    return True


# ============================================================
# FREEZE CANDIDATE
# ============================================================

def freeze_candidate(
    candidate,
    request_calibration,
    request_tokenizer,
    allowed_reasons,
):
    """
    Always returns the exact public candidate response shape.

    Invalid files result in:
        inventory=[]
        totalBytes=null
        packageDigest=null
    """

    name = candidate.get("name")

    # Candidate structural problems are represented as invalid.
    if not nonempty_string(name):
        name = ""

    files = candidate.get("files")

    files_valid, inventory, total_bytes, package_digest = (
        build_inventory(files)
    )

    if not files_valid:
        return {
            "name": name,
            "status": "invalid",
            "inventory": [],
            "totalBytes": None,
            "packageDigest": None,
            "reasonCodes": [],
        }, {
            "lineageValid": False,
            "manifestValid": False,
        }

    reasons = set()

    unsupported_reason = candidate.get(
        "unsupportedReason"
    )

    # --------------------------------------------------------
    # Explicit unsupported reason.
    # --------------------------------------------------------

    if (
        isinstance(unsupported_reason, str)
        and len(unsupported_reason) > 0
    ):

        if unsupported_reason in allowed_reasons:

            return {
                "name": name,
                "status": "unsupported",
                "inventory": inventory,
                "totalBytes": total_bytes,
                "packageDigest": package_digest,
                "reasonCodes": [],
            }, {
                "lineageValid": False,
                "manifestValid": False,
            }

        add_code(
            reasons,
            "UNALLOWED_UNSUPPORTED_REASON",
        )

        return {
            "name": name,
            "status": "invalid",
            "inventory": inventory,
            "totalBytes": total_bytes,
            "packageDigest": package_digest,
            "reasonCodes": sorted_codes(reasons),
        }, {
            "lineageValid": False,
            "manifestValid": False,
        }

    # --------------------------------------------------------
    # No unsupported reason:
    #
    # Candidate must be loadable and have matching lineage.
    # --------------------------------------------------------

    if candidate.get("loadable") is not True:
        add_code(
            reasons,
            "NOT_LOADABLE",
        )

    if candidate.get(
        "calibrationDigest"
    ) != request_calibration:
        add_code(
            reasons,
            "CALIBRATION_MISMATCH",
        )

    if candidate.get(
        "tokenizerDigest"
    ) != request_tokenizer:
        add_code(
            reasons,
            "TOKENIZER_MISMATCH",
        )

    if reasons:
        return {
            "name": name,
            "status": "invalid",
            "inventory": inventory,
            "totalBytes": total_bytes,
            "packageDigest": package_digest,
            "reasonCodes": sorted_codes(reasons),
        }, {
            "lineageValid": False,
            "manifestValid": False,
        }

    # --------------------------------------------------------
    # Valid frozen candidate.
    # --------------------------------------------------------

    return {
        "name": name,
        "status": "frozen",
        "inventory": inventory,
        "totalBytes": total_bytes,
        "packageDigest": package_digest,
        "reasonCodes": [],
    }, {
        "lineageValid": True,
        "manifestValid": True,
    }


# ============================================================
# FREEZE
# ============================================================

def handle_freeze(body):
    freeze_id = body["freezeId"]

    # --------------------------------------------------------
    # Canonical freeze input.
    #
    # This is used for exact replay/conflict detection.
    # --------------------------------------------------------

    request_signature = canonical_json(body)

    if freeze_id in FREEZES:

        existing = FREEZES[freeze_id]

        if (
            existing["request"]
            == request_signature
        ):
            return (
                200,
                copy.deepcopy(
                    existing["response"]
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
    # Candidate names must be unique.
    #
    # This is a freeze-input problem.
    # --------------------------------------------------------

    names = []

    for candidate in body["candidates"]:

        if not isinstance(candidate, dict):
            return (
                400,
                {
                    "error":
                        "INVALID_INPUT"
                },
            )

        name = candidate.get("name")

        if not nonempty_string(name):
            return (
                400,
                {
                    "error":
                        "INVALID_INPUT"
                },
            )

        names.append(name)

    if len(names) != len(set(names)):
        return (
            400,
            {
                "error":
                    "INVALID_INPUT"
            },
        )

    # --------------------------------------------------------
    # Freeze every candidate.
    # --------------------------------------------------------

    frozen = []
    internal = {}

    allowed = set(
        body["allowedUnsupportedReasons"]
    )

    for candidate in body["candidates"]:

        public_candidate, internal_info = (
            freeze_candidate(
                candidate,
                body["calibrationDigest"],
                body["tokenizerDigest"],
                allowed,
            )
        )

        frozen.append(
            public_candidate
        )

        internal[
            public_candidate["name"]
        ] = {
            "source": copy.deepcopy(
                candidate
            ),
            **internal_info,
        }

    # --------------------------------------------------------
    # Sort candidates by UTF-8 name.
    # --------------------------------------------------------

    frozen.sort(
        key=lambda x: x["name"].encode("utf-8")
    )

    response = {
        "freezeId": freeze_id,
        "candidates": frozen,
    }

    # --------------------------------------------------------
    # Persist complete freeze state.
    # --------------------------------------------------------

    FREEZES[freeze_id] = {
        "request": request_signature,
        "response": copy.deepcopy(
            response
        ),
        "internal": internal,
    }

    return 200, response


# ============================================================
# SELECT VALIDATION
# ============================================================

def validate_select_top_level(body):
    """
    Explicit INVALID_INPUT cases from the prompt.
    """

    if not isinstance(body, dict):
        return False

    if body.get("phase") != "select":
        return False

    if not nonempty_string(
        body.get("freezeId")
    ):
        return False

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

    if not isinstance(
        body.get("policy"),
        dict,
    ):
        return False

    if not isinstance(
        body.get("latencies"),
        dict,
    ):
        return False

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

    if not isinstance(
        policy["requiredSlices"],
        dict,
    ):
        return False

    for value in policy[
        "requiredSlices"
    ].values():

        if not finite_unit(value):
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
# CANDIDATE MANIFEST RECOMPUTATION
# ============================================================

def recompute_candidate_manifest(candidate):
    """
    Never trust totalBytes/packageDigest supplied by select.
    """

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

    # Exact inventory entry structure.
    for entry in inventory:

        if not isinstance(entry, dict):
            return None

        if list(entry.keys()) != [
            "name",
            "bytes",
            "sha256",
        ]:
            return None

        if not nonempty_string(
            entry["name"]
        ):
            return None

        if not safe_nonnegative_int(
            entry["bytes"]
        ):
            return None

        if (
            not isinstance(
                entry["sha256"],
                str,
            )
            or len(entry["sha256"]) != 64
            or entry["sha256"]
            != entry["sha256"].lower()
        ):
            return None

    # Inventory must be sorted by UTF-8 filename.
    names = [
        entry["name"]
        for entry in inventory
    ]

    if names != sorted(
        names,
        key=utf8_sort_key,
    ):
        return None

    # Names must be unique.
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
# PREDICTION VALIDATION
# ============================================================

def prediction_is_binary(value):
    """
    Binary means exactly integer 0 or 1.
    """

    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value in (0, 1)
    )


def round12(value):
    return round(
        value,
        12,
    )


def compute_metrics(
    candidate_name,
    rows,
    required_slices,
):
    """
    Returns:
        valid,
        aggregate,
        slices,
        invalid_predictions
    """

    if len(rows) == 0:
        # No rows means accuracy cannot be established.
        return (
            False,
            None,
            {
                name: None
                for name in required_slices
            },
            True,
        )

    total_correct = 0

    slice_correct = {
        name: 0
        for name in required_slices
    }

    slice_total = {
        name: 0
        for name in required_slices
    }

    for row in rows:

        if not isinstance(row, dict):
            return (
                False,
                None,
                {
                    name: None
                    for name in required_slices
                },
                True,
            )

        if "label" not in row:
            return (
                False,
                None,
                {
                    name: None
                    for name in required_slices
                },
                True,
            )

        if "slice" not in row:
            return (
                False,
                None,
                {
                    name: None
                    for name in required_slices
                },
                True,
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
                True,
            )

        if candidate_name not in predictions:
            return (
                False,
                None,
                {
                    name: None
                    for name in required_slices
                },
                True,
            )

        prediction = predictions[
            candidate_name
        ]

        if not prediction_is_binary(
            prediction
        ):
            return (
                False,
                None,
                {
                    name: None
                    for name in required_slices
                },
                True,
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

    aggregate = round12(
        total_correct / len(rows)
    )

    slices = {}

    for name in required_slices:

        if slice_total[name] == 0:
            slices[name] = None
        else:
            slices[name] = round12(
                slice_correct[name]
                / slice_total[name]
            )

    return (
        True,
        aggregate,
        slices,
        False,
    )


# ============================================================
# SELECT CANDIDATE
# ============================================================

def evaluate_candidate(
    stored_candidate,
    submitted_candidate,
    rows,
    policy,
    latencies,
    internal_info,
):
    name = stored_candidate["name"]

    codes = set()

    # --------------------------------------------------------
    # Lineage / frozen state.
    # --------------------------------------------------------

    if stored_candidate["status"] != "frozen":
        add_code(
            codes,
            "NOT_FROZEN",
        )

    if not internal_info.get(
        "lineageValid",
        False,
    ):
        add_code(
            codes,
            "INVALID_LINEAGE",
        )

    if not internal_info.get(
        "manifestValid",
        False,
    ):
        add_code(
            codes,
            "INVALID_MANIFEST",
        )

    # --------------------------------------------------------
    # Recompute manifest.
    # --------------------------------------------------------

    manifest = recompute_candidate_manifest(
        submitted_candidate
    )

    total_bytes = None

    if manifest is None:
        add_code(
            codes,
            "INVALID_MANIFEST",
        )

    else:

        total_bytes = manifest[
            "totalBytes"
        ]

        # Compare against stored frozen response.
        if (
            manifest["inventory"]
            != stored_candidate["inventory"]
            or manifest["packageDigest"]
            != stored_candidate["packageDigest"]
            or manifest["totalBytes"]
            != stored_candidate["totalBytes"]
        ):
            add_code(
                codes,
                "INVALID_MANIFEST",
            )

    # --------------------------------------------------------
    # Latency.
    # --------------------------------------------------------

    latency = None

    if (
        isinstance(latencies, dict)
        and name in latencies
        and finite_nonnegative(
            latencies[name]
        )
    ):
        latency = latencies[name]
    else:
        add_code(
            codes,
            "LATENCY_LIMIT",
        )

    # --------------------------------------------------------
    # Predictions.
    # --------------------------------------------------------

    (
        prediction_valid,
        aggregate,
        slices,
        _,
    ) = compute_metrics(
        name,
        rows,
        policy["requiredSlices"],
    )

    if not prediction_valid:

        add_code(
            codes,
            "INVALID_PREDICTIONS",
        )

        aggregate = None

        slices = {
            slice_name: None
            for slice_name
            in policy[
                "requiredSlices"
            ]
        }

    # --------------------------------------------------------
    # Aggregate floor.
    # --------------------------------------------------------

    if aggregate is not None:

        if (
            aggregate
            < policy["aggregateFloor"]
        ):
            add_code(
                codes,
                "AGGREGATE_FLOOR",
            )

    # --------------------------------------------------------
    # Required slices.
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

            add_code(
                codes,
                f"MISSING_SLICE:{slice_name}",
            )

        elif value < floor:

            add_code(
                codes,
                f"SLICE_FLOOR:{slice_name}",
            )

    # --------------------------------------------------------
    # Size.
    # --------------------------------------------------------

    if (
        total_bytes is not None
        and total_bytes
        > policy["maxBytes"]
    ):
        add_code(
            codes,
            "SIZE_LIMIT",
        )

    # --------------------------------------------------------
    # Latency.
    # --------------------------------------------------------

    if (
        latency is not None
        and latency
        > policy["maxLatencyMs"]
    ):
        add_code(
            codes,
            "LATENCY_LIMIT",
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
    # Unknown freeze.
    # --------------------------------------------------------

    if freeze_id not in FREEZES:

        # We still produce a deterministic response for the
        # supplied candidate names.
        names = []

        for candidate in body["candidates"]:
            if (
                isinstance(candidate, dict)
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
                    k: None
                    for k in body[
                        "policy"
                    ].get(
                        "requiredSlices",
                        {},
                    )
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

    record = FREEZES[freeze_id]

    stored_response = record["response"]

    stored_candidates = {
        c["name"]: c
        for c in stored_response[
            "candidates"
        ]
    }

    # --------------------------------------------------------
    # Policy validation.
    # --------------------------------------------------------

    policy = body["policy"]

    if not validate_policy(policy):

        results = []

        for candidate in body["candidates"]:

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

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None,
        }

    # --------------------------------------------------------
    # Candidate names.
    # --------------------------------------------------------

    submitted_names = []

    for candidate in body[
        "candidates"
    ]:

        if not isinstance(
            candidate,
            dict,
        ):
            submitted_names.append("")
        else:
            submitted_names.append(
                candidate.get(
                    "name",
                    "",
                )
            )

    stored_names = set(
        stored_candidates.keys()
    )

    submitted_name_set = set(
        submitted_names
    )

    candidate_order = policy[
        "candidateOrder"
    ]

    # Candidate order must equal candidate set.
    if (
        submitted_name_set
        != stored_names
        or set(candidate_order)
        != stored_names
        or len(candidate_order)
        != len(stored_names)
    ):

        results = []

        for name in sorted(
            submitted_name_set,
            key=utf8_sort_key,
        ):

            results.append({
                "name": name,
                "aggregate": None,
                "slices": {
                    k: None
                    for k in policy[
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
    # Candidate response must EXACTLY equal stored freeze
    # --------------------------------------------------------

    submitted_by_name = {
        c["name"]: c
        for c in body[
            "candidates"
        ]
        if isinstance(c, dict)
        and nonempty_string(
            c.get("name")
        )
    }

    # --------------------------------------------------------
    # Evaluate.
    # --------------------------------------------------------

    results_by_name = {}

    for name in stored_names:

        stored = stored_candidates[
            name
        ]

        submitted = submitted_by_name.get(
            name
        )

        if submitted is None:

            results_by_name[name] = {
                "name": name,
                "aggregate": None,
                "slices": {
                    k: None
                    for k in policy[
                        "requiredSlices"
                    ]
                },
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": [
                    "INVALID_LINEAGE"
                ],
            }

            continue

        # Exact equality against persisted freeze response.
        if canonical_json(
            submitted
        ) != canonical_json(
            stored
        ):

            results_by_name[name] = {
                "name": name,
                "aggregate": None,
                "slices": {
                    k: None
                    for k in policy[
                        "requiredSlices"
                    ]
                },
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": [
                    "INVALID_LINEAGE"
                ],
            }

            continue

        internal_info = record[
            "internal"
        ].get(
            name,
            {},
        )

        results_by_name[name] = (
            evaluate_candidate(
                stored,
                submitted,
                body["rows"],
                policy,
                body["latencies"],
                internal_info,
            )
        )

    # --------------------------------------------------------
    # Candidate result ordering.
    #
    # candidateOrder is authoritative.
    # UTF-8 name is fallback.
    # --------------------------------------------------------

    order_index = {
        name: i
        for i, name
        in enumerate(candidate_order)
    }

    results = sorted(
        results_by_name.values(),
        key=lambda r: (
            order_index.get(
                r["name"],
                len(candidate_order),
            ),
            utf8_sort_key(
                r["name"]
            ),
        ),
    )

    # --------------------------------------------------------
    # Winner.
    #
    # admitted candidates:
    #   smaller bytes
    #   lower latency
    #   candidateOrder
    # --------------------------------------------------------

    admitted = [
        result
        for result in results
        if result["admitted"]
    ]

    def winner_key(result):
        return (
            result["totalBytes"],
            result["latencyMs"],
            order_index[
                result["name"]
            ],
        )

    admitted.sort(
        key=winner_key
    )

    selected = None
    package_manifest = None

    if admitted:

        winner = admitted[0]

        selected = winner["name"]

        package_manifest = copy.deepcopy(
            stored_candidates[
                selected
            ]
        )

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest,
    }


# ============================================================
# ENDPOINT
# ============================================================

@app.post("/quantize")
async def quantize(request: Request):

    # --------------------------------------------------------
    # JSON parsing
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # FREEZE
    # --------------------------------------------------------

    if phase == "freeze":

        if not validate_freeze_top_level(
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

    # --------------------------------------------------------
    # SELECT
    # --------------------------------------------------------

    if phase == "select":

        if not validate_select_top_level(
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

    # --------------------------------------------------------
    # Unknown/missing phase.
    # --------------------------------------------------------

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
