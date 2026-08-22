from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import threading

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / "bin" / "claude-drop"
CANARY = b"claude-drop-canary-never-on-stdout"


def serve_once(path: Path, response: dict, captured: list[dict]) -> threading.Thread:
    ready = threading.Event()

    def run() -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(path))
            server.listen(1)
            ready.set()
            conn, _ = server.accept()
            with conn:
                raw = b""
                while b"\n" not in raw:
                    raw += conn.recv(4096)
                captured.append(json.loads(raw.split(b"\n", 1)[0]))
                conn.sendall(json.dumps(response).encode() + b"\n")

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert ready.wait(2)
    return thread


def run_client(tmp_path: Path, socket_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update({
        "HERMES_DROP_CONTROL_SOCKET": str(socket_path),
        "XDG_RUNTIME_DIR": str(tmp_path / "runtime"),
        "DISPLAY": "",
        "WAYLAND_DISPLAY": "",
        "PATH": "/usr/bin:/bin",
    })
    (tmp_path / "runtime").mkdir()
    return subprocess.run(
        [str(CLIENT), *args], env=env, text=True, capture_output=True, timeout=10, check=False
    )


def test_request_keeps_notice_off_stdout_and_in_a_private_file(tmp_path: Path) -> None:
    sock = tmp_path / "control.sock"
    captured: list[dict] = []
    capability = "https://drop.invalid/#CAPABILITY"
    thread = serve_once(sock, {"ok": True, "handoff_id": "H" * 22, "notice": capability}, captured)

    result = run_client(tmp_path, sock, "request")
    thread.join(2)

    assert result.returncode == 0
    assert capability not in result.stdout + result.stderr
    receipt = json.loads(result.stdout)
    notice_path = Path(receipt["path"])
    assert notice_path.read_text() == capability
    assert notice_path.stat().st_mode & 0o777 == 0o600
    assert captured == [{"op": "create", "notice_platform": "plain", "payload_kind": "universal"}]


def test_claim_keeps_plaintext_off_stdout_and_materializes_0600(tmp_path: Path) -> None:
    sock = tmp_path / "control.sock"
    captured: list[dict] = []
    import base64

    thread = serve_once(sock, {"ok": True, "plaintext_b64": base64.b64encode(CANARY).decode()}, captured)
    result = run_client(tmp_path, sock, "claim", "H" * 22)
    thread.join(2)

    assert result.returncode == 0
    assert CANARY.decode() not in result.stdout + result.stderr
    receipt = json.loads(result.stdout)
    secret_path = Path(receipt["path"])
    assert secret_path.read_bytes() == CANARY
    assert secret_path.stat().st_mode & 0o777 == 0o600
    assert captured[0]["op"] == "claim"


def test_generated_outbound_request_contains_generation_not_plaintext(tmp_path: Path) -> None:
    sock = tmp_path / "control.sock"
    captured: list[dict] = []
    thread = serve_once(sock, {"ok": True, "drop_id": "D" * 22, "notice": "private notice"}, captured)
    result = run_client(tmp_path, sock, "send-generated", "--label", "Admin password")
    thread.join(2)

    assert result.returncode == 0
    assert "private notice" not in result.stdout + result.stderr
    import base64
    payload = json.loads(base64.b64decode(captured[0]["plaintext_b64"]))
    assert payload["fields"][0]["generate"] == {"kind": "password", "length": 32}
    assert "value" not in payload["fields"][0]
