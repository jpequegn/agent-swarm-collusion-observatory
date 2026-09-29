#!/usr/bin/env python3
"""Run the documented offline checks and exercise both CLI and loopback UI."""

from __future__ import annotations

import http.cookiejar
import json
import os
import re
import selectors
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def require_tools() -> tuple[str, str]:
    if sys.version_info < (3, 12):
        raise RuntimeError("Python 3.12 or newer is required")
    go = shutil.which("go")
    make = shutil.which("make")
    if not go:
        raise RuntimeError("Go 1.25 or newer is required on PATH")
    if not make:
        raise RuntimeError("GNU Make is required on PATH")
    version = subprocess.run([go, "version"], check=True, capture_output=True, text=True).stdout
    match = re.search(r"\bgo(\d+)\.(\d+)", version)
    if not match or tuple(map(int, match.groups())) < (1, 25):
        raise RuntimeError(f"Go 1.25 or newer is required, found: {version.strip()}")
    return go, make


def writable_go_cache(go: str, fallback: Path) -> str:
    configured = os.environ.get("GOCACHE")
    if not configured:
        configured = subprocess.run(
            [go, "env", "GOCACHE"], check=True, capture_output=True, text=True
        ).stdout.strip()
    try:
        with tempfile.TemporaryFile(dir=configured):
            pass
        return configured
    except OSError:
        fallback.mkdir(parents=True, exist_ok=True)
        return str(fallback)


def run(label: str, command: list[str], env: dict[str, str] | None = None) -> str:
    print(f"== {label} ==", flush=True)
    result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(
            f"{label} failed with exit code {result.returncode}\n"
            f"$ {' '.join(command)}\n{result.stdout}{result.stderr}"
        )
    return result.stdout


def cli_json(binary: Path, *args: str) -> dict:
    output = run("observatory " + args[0], [str(binary), *args])
    return json.loads(output)


def check_cli(binary: Path, store: Path) -> None:
    fixtures = cli_json(binary, "fixtures")
    available = {item["id"] for item in fixtures["fixtures"]}
    expected = {"honest-coordination", "collusion-reward-gaming"}
    if not expected.issubset(available):
        raise RuntimeError(f"fixture catalog is missing {sorted(expected - available)}")

    demonstrations = (
        ("honest-coordination", "shared_messages", "honest_repair"),
        ("collusion-reward-gaming", "hierarchical", "reward_gamer"),
    )
    for fixture, topology, worker_policy in demonstrations:
        result = cli_json(
            binary,
            "run",
            "--fixture",
            fixture,
            "--topology",
            topology,
            "--worker-policy",
            worker_policy,
            "--repo",
            str(ROOT),
            "--store",
            str(store),
        )
        if not result.get("completed"):
            raise RuntimeError(f"fixture {fixture} did not complete")
        run_id = result["run_id"]
        verification = cli_json(binary, "verify", "--run-id", run_id, "--store", str(store))
        if not verification.get("verified") or not verification.get("completed"):
            raise RuntimeError(f"fixture {fixture} did not pass ledger verification")
        evaluation = cli_json(binary, "evaluate", "--run-id", run_id, "--store", str(store))
        if not evaluation.get("evidence_integrity", {}).get("verified"):
            raise RuntimeError(f"fixture {fixture} did not produce a verified evaluation")
        replay = cli_json(binary, "replay", "--run-id", run_id, "--store", str(store))
        if not replay.get("faithful"):
            raise RuntimeError(f"fixture {fixture} did not replay faithfully")
        print(f"PASS {fixture}: verified, evaluated, and replayed", flush=True)


def request_json(
    opener: urllib.request.OpenerDirector,
    url: str,
    method: str = "GET",
    data: dict | None = None,
    headers: dict[str, str] | None = None,
) -> dict | str:
    request_headers = dict(headers or {})
    encoded = None
    if data is not None:
        encoded = json.dumps(data).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=encoded, headers=request_headers, method=method)
    with opener.open(request, timeout=10) as response:
        content = response.read().decode("utf-8")
        if response.headers.get_content_type() == "application/json":
            return json.loads(content)
        return content


def start_ui(binary: Path, store: Path) -> tuple[subprocess.Popen[str], str]:
    process = subprocess.Popen(
        [str(binary), "ui", "--port", "0", "--store", str(store), "--repo", str(ROOT)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if process.stderr is None:
        raise RuntimeError("could not capture UI startup output")
    selector = selectors.DefaultSelector()
    selector.register(process.stderr, selectors.EVENT_READ)
    deadline = time.monotonic() + 60
    startup_output = []
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            if not selector.select(timeout=0.25):
                continue
            line = process.stderr.readline()
            startup_output.append(line)
            line = line.strip()
            if line.startswith("Observatory UI: "):
                address = line.removeprefix("Observatory UI: ")
                if urllib.parse.urlsplit(address).hostname != "127.0.0.1":
                    raise RuntimeError(f"UI did not bind to IPv4 loopback: {address}")
                return process, address
        startup_output.append(process.stderr.read())
        details = "".join(startup_output).strip()
        raise RuntimeError(f"UI did not start within 60 seconds (exit={process.poll()}): {details}")
    except BaseException:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        raise
    finally:
        selector.close()


def stop_ui(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def check_ui(binary: Path, store: Path) -> None:
    process, base = start_ui(binary, store)
    try:
        cookies = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
        page = request_json(opener, base + "/")
        if not isinstance(page, str) or "/ui.js" not in page:
            raise RuntimeError("UI page did not load its embedded application")
        catalog = request_json(opener, base + "/api/fixtures")
        if not catalog.get("fixtures"):
            raise RuntimeError("UI fixture catalog is empty")
        session = request_json(opener, base + "/api/session")
        token = session.get("csrf_token", "")
        if not token:
            raise RuntimeError("UI session did not return a CSRF token")

        origin = urllib.parse.urlsplit(base)
        origin_value = f"{origin.scheme}://{origin.netloc}"
        detail = request_json(
            opener,
            base + "/api/runs",
            method="POST",
            data={
                "fixture": "honest-coordination",
                "topology": "hierarchical",
                "worker_policy": "honest_repair",
            },
            headers={"Origin": origin_value, "X-CSRF-Token": token},
        )
        run_id = detail["run_id"]
        if not detail.get("completed") or not detail.get("integrity_verified") or "truth_records" in detail:
            raise RuntimeError("UI run response was incomplete, unverified, or exposed truth")
        verification = request_json(opener, f"{base}/api/runs/{run_id}/verify")
        evaluation = request_json(opener, f"{base}/api/runs/{run_id}/evaluation")
        truth = request_json(opener, f"{base}/api/runs/{run_id}/truth")
        if not verification.get("verified") or not evaluation.get("evidence_integrity", {}).get("verified"):
            raise RuntimeError("UI verification or evaluation failed")
        if not truth.get("verified") or not truth.get("truth_records"):
            raise RuntimeError("UI explicit truth projection was unavailable after verification")
        replay = request_json(
            opener,
            f"{base}/api/runs/{run_id}/replay",
            method="POST",
            data={},
            headers={"Origin": origin_value, "X-CSRF-Token": token},
        )
        if not replay.get("faithful"):
            raise RuntimeError("UI replay did not verify as faithful")

        try:
            request_json(
                opener,
                base + "/api/runs",
                method="POST",
                data={"fixture": "honest-coordination", "topology": "shared_messages"},
                headers={"Origin": "http://attacker.invalid", "X-CSRF-Token": token},
            )
        except urllib.error.HTTPError as error:
            if error.code != 403:
                raise RuntimeError(f"cross-origin mutation returned HTTP {error.code}, expected 403") from error
        else:
            raise RuntimeError("UI accepted a cross-origin mutation")
        print("PASS loopback UI: page, run, verify, evaluate, truth, replay, and origin guard", flush=True)
    finally:
        stop_ui(process)


def main() -> int:
    try:
        go, _ = require_tools()
        with tempfile.TemporaryDirectory(prefix="agent-swarm-observatory-") as temporary:
            temp = Path(temporary)
            env = os.environ.copy()
            env["PYTHON"] = sys.executable
            env["GOCACHE"] = writable_go_cache(go, temp / "go-cache")
            run("make check", ["make", "check"], env)
            binary = temp / "observatory"
            store = temp / "cli-runs"
            ui_store = temp / "ui-runs"
            run("build CLI", [go, "build", "-o", str(binary), "./cmd/observatory"], env)
            check_cli(binary, store)
            check_ui(binary, ui_store)
        print("Clean-checkout gate passed.", flush=True)
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(f"Clean-checkout gate failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
