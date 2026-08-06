from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from typing import Any, Mapping
import json


def stable_hash(value: Any) -> str:
    def norm(v: Any) -> Any:
        if isinstance(v, Mapping):
            return {str(k): norm(x) for k, x in sorted(v.items())}
        if isinstance(v, (list, tuple)):
            return [norm(x) for x in v]
        return v
    return sha256(json.dumps(norm(value), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def frozen_redacted_observation() -> dict[str, Any]:
    observation = {
        "schema": "arte.redacted_private_actions_discrimination/v1",
        "same_account": True,
        "same_standard_runner_label": True,
        "controls": [
            {"label": "PUBLIC_CONTROL", "visibility": "public", "rerun_or_run_accepted": True, "conclusion": "success", "step_count": 3, "marker_present": True, "log_blob_present": True},
            {"label": "PRIVATE_CONTROL_A", "visibility": "private", "rerun_or_run_accepted": True, "conclusion": "failure", "step_count": 0, "marker_present": False, "log_blob_present": False},
            {"label": "PRIVATE_CONTROL_B", "visibility": "private", "rerun_or_run_accepted": True, "conclusion": "failure", "step_count": 0, "marker_present": False, "log_blob_present": False},
        ],
        "public_service_status_operational": True,
        "redaction": {"repository_names_removed": True, "run_ids_removed": True, "job_ids_removed": True, "source_code_removed": True},
    }
    observation["observation_hash"] = stable_hash(observation)
    return observation


def classify(observation: Mapping[str, Any]) -> dict[str, Any]:
    raw = deepcopy(dict(observation)); supplied = raw.pop("observation_hash", None)
    valid = supplied == stable_hash(raw)
    rows = list(observation.get("controls", []))
    public = [row for row in rows if row.get("visibility") == "public"]
    private = [row for row in rows if row.get("visibility") == "private"]
    public_executed = len(public) == 1 and public[0].get("conclusion") == "success" and public[0].get("step_count", 0) >= 1 and public[0].get("marker_present") is True and public[0].get("log_blob_present") is True
    private_prestep = len(private) == 2 and all(row.get("conclusion") == "failure" and row.get("step_count") == 0 and row.get("log_blob_present") is False for row in private)
    same_surface = observation.get("same_account") is True and observation.get("same_standard_runner_label") is True

    if valid and same_surface and public_executed and private_prestep:
        diagnosis = "PRIVATE_REPOSITORY_ACTIONS_EXECUTION_SURFACE_BLOCKER"
        unresolved = ["PRIVATE_ACTIONS_BILLING_QUOTA_OR_ZERO_BUDGET", "PRIVATE_REPOSITORY_ACTIONS_POLICY_RESTRICTION"]
        eliminated = ["ACCOUNT_WIDE_STANDARD_HOSTED_RUNNER_UNAVAILABLE", "GLOBAL_GITHUB_ACTIONS_OUTAGE", "APPLICATION_OR_TEST_CODE_FAILURE", "CHECKOUT_OR_EXTERNAL_ACTION_DEPENDENCY_FAILURE"]
    elif valid and same_surface and not public_executed and private_prestep:
        diagnosis = "ACCOUNT_OR_HOSTED_RUNNER_EXECUTION_SURFACE_BLOCKER"
        unresolved = ["ACCOUNT_LEVEL_RESTRICTION", "HOSTED_RUNNER_ALLOCATION_ANOMALY", "GLOBAL_OR_REGIONAL_RUNNER_FAILURE"]
        eliminated = []
    elif valid and any(row.get("step_count", 0) >= 1 for row in private):
        diagnosis = "PRIVATE_EXECUTED_JOB_FAILURE"
        unresolved = ["INSPECT_PRIVATE_STEP_LOGS"]
        eliminated = ["PRIVATE_PRESTEP_BLOCKER"]
    else:
        diagnosis = "INSUFFICIENT_DISCRIMINATION_EVIDENCE"
        unresolved = ["NULL"]
        eliminated = []

    result = {
        "schema": "arte.redacted_private_actions_discrimination_result/v1",
        "source_observation_hash": supplied,
        "diagnosis": diagnosis,
        "unresolved_hypotheses": unresolved,
        "eliminated_hypotheses": eliminated,
        "next_action_order": ["CHECK_PRIVATE_ACTIONS_BILLING_INCLUDED_MINUTES_AND_BUDGET", "CHECK_PRIVATE_REPOSITORY_ACTIONS_GENERAL_POLICY", "RERUN_BOTH_PRIVATE_MINIMAL_CONTROLS", "OPEN_GITHUB_SUPPORT_CASE_IF_STILL_PRESTEP"] if diagnosis == "PRIVATE_REPOSITORY_ACTIONS_EXECUTION_SURFACE_BLOCKER" else ["NULL"],
        "exact_root_cause_known": False,
        "remote_public_control_passed": public_executed,
        "private_execution_recovered": False,
        "claim_boundary": {"redacted_public_verification_only": True, "private_settings_read": False, "billing_verified": False, "independent_evaluation": False, "external_authority": False, "promotion": False, "agi": False, "asi": False},
    }
    result["result_hash"] = stable_hash(result)
    return result


def counterfactual(arm: str) -> dict[str, Any]:
    obs = frozen_redacted_observation(); rows = obs["controls"]
    if arm == "FULL":
        pass
    elif arm == "PUBLIC_SUCCESS_REMOVAL":
        pub = next(row for row in rows if row["visibility"] == "public"); pub.update({"conclusion": "failure", "step_count": 0, "marker_present": False, "log_blob_present": False})
    elif arm == "PRIVATE_STEP_WRONG_SWAP":
        prv = next(row for row in rows if row["visibility"] == "private"); prv.update({"conclusion": "failure", "step_count": 2, "marker_present": True, "log_blob_present": True})
    elif arm == "VISIBILITY_WRONG_SWAP":
        for row in rows:
            if row["label"] == "PUBLIC_CONTROL": row["visibility"] = "private"
            elif row["label"] == "PRIVATE_CONTROL_A": row["visibility"] = "public"
    else:
        raise ValueError(arm)
    obs.pop("observation_hash", None); obs["observation_hash"] = stable_hash(obs)
    return classify(obs)


def build_packet() -> dict[str, Any]:
    arms = ("FULL", "PUBLIC_SUCCESS_REMOVAL", "PRIVATE_STEP_WRONG_SWAP", "VISIBILITY_WRONG_SWAP")
    results = {arm: counterfactual(arm) for arm in arms}
    packet = {
        "schema": "arte.redacted_private_actions_discrimination_packet/v1",
        "observation": frozen_redacted_observation(),
        "frozen_arms": list(arms),
        "results": results,
        "checks": {
            "full_private_scope_supported": results["FULL"]["diagnosis"] == "PRIVATE_REPOSITORY_ACTIONS_EXECUTION_SURFACE_BLOCKER",
            "public_success_is_necessary": results["PUBLIC_SUCCESS_REMOVAL"]["diagnosis"] == "ACCOUNT_OR_HOSTED_RUNNER_EXECUTION_SURFACE_BLOCKER",
            "private_executed_step_changes_diagnosis": results["PRIVATE_STEP_WRONG_SWAP"]["diagnosis"] == "PRIVATE_EXECUTED_JOB_FAILURE",
            "visibility_swap_breaks_full_diagnosis": results["VISIBILITY_WRONG_SWAP"]["diagnosis"] != results["FULL"]["diagnosis"],
        },
        "authority": {"disposition": "SHADOW_PUBLIC_REMOTE_DISCRIMINATION_CANDIDATE", "external_authority": False, "promotion": False},
        "claim_boundary": {"private_billing_verified": False, "private_settings_read": False, "private_execution_recovered": False, "independent_evaluation": False, "foundation_model_weight_learning": False, "agi": False, "asi": False},
    }
    packet["packet_hash"] = stable_hash(packet)
    return packet


def validate_packet(packet: Mapping[str, Any]) -> list[str]:
    raw = deepcopy(dict(packet)); supplied = raw.pop("packet_hash", None); problems = []
    if supplied != stable_hash(raw): problems.append("packet_hash_mismatch")
    for field, value in packet.get("checks", {}).items():
        if value is not True: problems.append(field)
    for field in ("private_billing_verified", "private_settings_read", "private_execution_recovered", "independent_evaluation", "foundation_model_weight_learning", "agi", "asi"):
        if packet.get("claim_boundary", {}).get(field) is not False: problems.append(f"claim_boundary:{field}")
    return problems


if __name__ == "__main__":
    packet = build_packet(); problems = validate_packet(packet)
    print(json.dumps({"packet_hash": packet["packet_hash"], "diagnosis": packet["results"]["FULL"]["diagnosis"], "validation_passed": not problems, "problems": problems}, indent=2, sort_keys=True))
    raise SystemExit(0 if not problems else 1)
