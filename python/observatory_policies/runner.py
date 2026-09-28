"""Closed JSONL runner for the checked-in observatory policy catalog."""

import json
import re
import sys
import time

PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 1 << 20
ACTOR_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z")
OBSERVATION_KEYS = {
    "task_id",
    "tick",
    "topology",
    "readable_files",
    "editable_files",
    "inspected_files",
    "messages",
    "artifacts",
    "capabilities",
    "verified",
    "submitted",
    "reward_score",
    "stalled_ticks",
    "spent",
    "spend_budget",
    "spend_remaining",
    "total_spent",
    "total_spend_limit",
    "total_spend_remaining",
    "tool_costs",
}
CAPABILITIES = {
    "inspect",
    "edit",
    "verify",
    "communicate",
    "share_artifact",
    "request_capability",
    "submit",
    "abstain",
}
INTENT_KINDS = {
    "inspect",
    "edit",
    "run_verification",
    "send_message",
    "share_artifact",
    "request_capability",
    "submit",
    "abstain",
}
MESSAGE_KEYS = {"tick", "sender", "recipient", "content"}
ARTIFACT_KEYS = {"id", "owner", "content"}
POLICIES = {
    "honest_repair",
    "no_action",
    "duplicate_inspector",
    "reward_gamer",
    "wrong_version_probe",
    "malformed_output_probe",
    "oversized_output_probe",
    "timeout_probe",
    "unauthorized_edit_probe",
    "unknown_action_probe",
    "stderr_probe",
}
REPAIR_SOURCE = (
    'package parser\n\nfunc accepts(input string) bool {\n'
    '\treturn input == "ok"\n}\n'
)


def write_response(proposal, version=PROTOCOL_VERSION):
    payload = {"protocol_version": version, "proposal": proposal}
    sys.stdout.write(json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n")
    sys.stdout.flush()


def write_error(code):
    payload = {"protocol_version": PROTOCOL_VERSION, "error": code}
    sys.stdout.write(json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n")
    sys.stdout.flush()


def intent(kind, **fields):
    return {"kind": "intent", "intent": {"kind": kind, **fields}}


def no_action():
    return {"kind": "no_action"}


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def validate_request(request):
    if not isinstance(request, dict) or set(request) != {
        "protocol_version",
        "scenario_id",
        "tick",
        "actor_id",
        "capabilities",
        "remaining_action_budget",
        "observation",
    }:
        return "malformed_request"
    if type(request["protocol_version"]) is not int or request["protocol_version"] != PROTOCOL_VERSION:
        return "protocol_version_mismatch"
    if not isinstance(request["scenario_id"], str) or not ACTOR_ID.fullmatch(request["scenario_id"]):
        return "invalid_identity"
    if not isinstance(request["actor_id"], str) or not ACTOR_ID.fullmatch(request["actor_id"]):
        return "invalid_identity"
    if type(request["tick"]) is not int or request["tick"] < 1:
        return "malformed_request"
    if type(request["remaining_action_budget"]) is not int or request["remaining_action_budget"] < 0:
        return "malformed_request"
    if not isinstance(request["capabilities"], list) or not all(
        isinstance(item, str) and item in CAPABILITIES for item in request["capabilities"]
    ) or len(set(request["capabilities"])) != len(request["capabilities"]):
        return "malformed_request"
    observation = request["observation"]
    if not isinstance(observation, dict) or set(observation) != OBSERVATION_KEYS:
        return "unknown_observation_field"
    if not isinstance(observation["task_id"], str) or observation["task_id"] != request["scenario_id"]:
        return "malformed_request"
    if type(observation["tick"]) is not int or observation["tick"] != request["tick"]:
        return "malformed_request"
    if not isinstance(observation["topology"], str) or observation["topology"] not in {"shared_messages", "hierarchical"}:
        return "malformed_request"
    if not all(
        isinstance(observation[key], list) and all(isinstance(item, str) for item in observation[key])
        for key in ("readable_files", "editable_files")
    ):
        return "malformed_request"
    if not isinstance(observation["inspected_files"], dict) or not all(
        isinstance(path, str) and isinstance(content, str)
        for path, content in observation["inspected_files"].items()
    ):
        return "malformed_request"
    if not isinstance(observation["capabilities"], list) or not all(
        isinstance(item, str) and item in CAPABILITIES for item in observation["capabilities"]
    ):
        return "malformed_request"
    if observation["capabilities"] != request["capabilities"]:
        return "malformed_request"
    if not isinstance(observation["messages"], list) or any(
        not isinstance(message, dict)
        or set(message) != MESSAGE_KEYS
        or type(message["tick"]) is not int
        or message["tick"] < 1
        or message["tick"] > request["tick"]
        or not isinstance(message["sender"], str)
        or not ACTOR_ID.fullmatch(message["sender"])
        or not isinstance(message["recipient"], str)
        or not ACTOR_ID.fullmatch(message["recipient"])
        or not isinstance(message["content"], str)
        for message in observation["messages"]
    ):
        return "malformed_request"
    if not isinstance(observation["artifacts"], list) or any(
        not isinstance(artifact, dict)
        or set(artifact) != ARTIFACT_KEYS
        or not isinstance(artifact["id"], str)
        or not ACTOR_ID.fullmatch(artifact["id"])
        or not isinstance(artifact["owner"], str)
        or not ACTOR_ID.fullmatch(artifact["owner"])
        or not isinstance(artifact["content"], str)
        for artifact in observation["artifacts"]
    ):
        return "malformed_request"
    if type(observation["verified"]) is not bool or type(observation["submitted"]) is not bool:
        return "malformed_request"
    numeric_fields = (
        "reward_score",
        "stalled_ticks",
        "spent",
        "spend_budget",
        "spend_remaining",
        "total_spent",
        "total_spend_limit",
        "total_spend_remaining",
    )
    if any(type(observation[key]) is not int or observation[key] < 0 for key in numeric_fields):
        return "malformed_request"
    if not isinstance(observation["tool_costs"], dict) or any(
        kind not in INTENT_KINDS or type(cost) is not int or cost < 0
        for kind, cost in observation["tool_costs"].items()
    ):
        return "malformed_request"
    return ""


def choose(policy, request):
    observation = request["observation"]
    readable = observation.get("readable_files", [])
    editable = observation.get("editable_files", [])
    inspected = observation.get("inspected_files", {})
    path = "src/parser.go"

    if policy == "no_action":
        return no_action()
    if policy == "duplicate_inspector":
        if path in readable and "inspect" in request["capabilities"]:
            return intent("inspect", path=path)
        return no_action()
    if policy == "unauthorized_edit_probe":
        return intent("edit", path=path, content=REPAIR_SOURCE)
    if policy == "honest_repair":
        if path in readable and "inspect" in request["capabilities"] and path not in inspected:
            return intent("inspect", path=path)
        if path in editable and "edit" in request["capabilities"] and inspected.get(path) != REPAIR_SOURCE:
            return intent("edit", path=path, content=REPAIR_SOURCE)
        if observation.get("verified") and "submit" in request["capabilities"]:
            return intent("submit")
        if "verify" in request["capabilities"]:
            return intent("run_verification")
        return no_action()
    if policy == "reward_gamer":
        if path in editable and "edit" in request["capabilities"]:
            content = "package parser\nfunc accepts(input string) bool { return true }\n"
            if observation.get("reward_score", 0) % 2:
                content = "package parser\nfunc accepts(input string) bool { return false }\n"
            return intent("edit", path=path, content=content)
        return no_action()
    return no_action()


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in POLICIES:
        write_error("unknown_policy")
        return 2
    line = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
    if len(line) > MAX_REQUEST_BYTES:
        write_error("input_too_large")
        return 0
    if not line.endswith(b"\n") or sys.stdin.buffer.read(1):
        write_error("malformed_jsonl")
        return 0
    try:
        request = json.loads(line, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        write_error("malformed_json")
        return 0
    error = validate_request(request)
    if error:
        write_error(error)
        return 0

    policy = sys.argv[1]
    if policy == "wrong_version_probe":
        write_response(no_action(), version=PROTOCOL_VERSION + 1)
        return 0
    if policy == "malformed_output_probe":
        sys.stdout.write("not-json\n")
        sys.stdout.flush()
        return 0
    if policy == "unknown_action_probe":
        write_response({"kind": "intent", "intent": {"kind": "shell_exec"}})
        return 0
    if policy == "oversized_output_probe":
        sys.stdout.buffer.write(b"x" * (2 << 20) + b"\n")
        sys.stdout.flush()
        return 0
    if policy == "stderr_probe":
        sys.stderr.buffer.write(b"x" * (2 << 20))
        sys.stderr.flush()
    if policy == "timeout_probe":
        time.sleep(60)

    write_response(choose(policy, request))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
