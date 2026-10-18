from __future__ import annotations

from fwagent.runtime.execution_policy import deny_unisolated_execution

import os
import signal
import socket
import struct
import subprocess
import time
from pathlib import Path
from typing import Any

from fwagent.dynamic.application import FastCGIHarnessResult


FCGI_VERSION = 1
FCGI_BEGIN_REQUEST = 1
FCGI_ABORT_REQUEST = 2
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6
FCGI_STDERR = 7
FCGI_RESPONDER = 1


def encode_begin_request(request_id: int = 1) -> bytes:
    body = struct.pack("!HB5x", FCGI_RESPONDER, 0)
    return _record(FCGI_BEGIN_REQUEST, request_id, body)


def encode_params(params: dict[str, str], request_id: int = 1) -> bytes:
    payload = b"".join(_name_value(name, value) for name, value in params.items())
    return _record(FCGI_PARAMS, request_id, payload) + _record(FCGI_PARAMS, request_id, b"")


def encode_stdin(data: bytes = b"", request_id: int = 1) -> bytes:
    return _record(FCGI_STDIN, request_id, data) + _record(FCGI_STDIN, request_id, b"")


def parse_fastcgi_response(data: bytes) -> dict[str, Any]:
    offset = 0
    stdout = bytearray()
    stderr = bytearray()
    end_request = None
    while offset + 8 <= len(data):
        version, record_type, request_id, content_length, padding_length, _reserved = struct.unpack(
            "!BBHHBB",
            data[offset : offset + 8],
        )
        offset += 8
        content = data[offset : offset + content_length]
        offset += content_length + padding_length
        if version != FCGI_VERSION:
            continue
        if record_type == FCGI_STDOUT:
            stdout.extend(content)
        elif record_type == FCGI_STDERR:
            stderr.extend(content)
        elif record_type == FCGI_END_REQUEST:
            end_request = {"request_id": request_id, "raw": content.hex()}
    stdout_text = stdout.decode("utf-8", errors="replace")
    status = _status_hint(stdout_text)
    return {
        "stdout": stdout_text,
        "stderr": stderr.decode("utf-8", errors="replace"),
        "end_request": end_request,
        "status_hint": status,
    }


@deny_unisolated_execution
def run_fastcgi_harness(
    command: list[str],
    *,
    runtime_dir: str | Path,
    socket_name: str = "fwagent-fastcgi.sock",
    params: dict[str, str] | None = None,
    timeout_seconds: int = 10,
    cwd: str | Path = "/",
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    if not hasattr(socket, "AF_UNIX"):
        return _blocked_result(
            "RUNTIME_ENVIRONMENT_BLOCKED",
            "AF_UNIX sockets are unavailable on this host Python runtime; standalone FastCGI FD0 harness requires a Unix-domain listening socket.",
            socket_path=str(Path(runtime_dir) / socket_name),
        )

    runtime = Path(runtime_dir)
    runtime.mkdir(parents=True, exist_ok=True)
    socket_path = runtime / socket_name
    try:
        socket_path.unlink()
    except FileNotFoundError:
        pass

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(5)
    os.chmod(socket_path, 0o777)

    start = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            stdin=listener,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd),
            env=env,
            close_fds=True,
            start_new_session=os.name != "nt",
        )
    except OSError as exc:
        listener.close()
        try:
            socket_path.unlink()
        except FileNotFoundError:
            pass
        return _blocked_result(
            "RUNTIME_ENVIRONMENT_BLOCKED",
            f"FastCGI child could not inherit the listening socket on this host runtime: {exc}",
            socket_path=str(socket_path),
        )
    listener.close()
    request_sent = False
    response = {"stdout": "", "stderr": "", "status_hint": None, "end_request": None}
    diagnosis = "backend_exited_before_request"
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(max(1, timeout_seconds // 2))
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            try:
                client.connect(str(socket_path))
                break
            except OSError:
                time.sleep(0.1)
        else:
            diagnosis = "fastcgi_socket_connect_timeout"
        if process.poll() is None:
            payload = (
                encode_begin_request()
                + encode_params(params or default_fastcgi_params())
                + encode_stdin()
            )
            client.sendall(payload)
            request_sent = True
            chunks = []
            client.settimeout(2)
            while True:
                try:
                    chunk = client.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                if b"\x01\x03" in chunk:
                    break
            response = parse_fastcgi_response(b"".join(chunks))
            diagnosis = "fastcgi_response_received" if response.get("stdout") or response.get("stderr") else "fastcgi_no_response"
        client.close()
    finally:
        alive_before_cleanup = process.poll() is None
        if alive_before_cleanup:
            try:
                process.wait(timeout=max(1, timeout_seconds - int(time.monotonic() - start)))
            except subprocess.TimeoutExpired:
                _terminate_process(process)
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    _kill_process(process)
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        pass
        try:
            stdout, stderr = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            _kill_process(process)
            try:
                stdout, stderr = process.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                stdout, stderr = b"", b""
        try:
            socket_path.unlink()
        except FileNotFoundError:
            pass

    final_code = process.returncode
    result = FastCGIHarnessResult(
        backend_started=True,
        backend_alive=alive_before_cleanup,
        socket_ready=socket_path.exists() or request_sent,
        request_sent=request_sent,
        response_received=bool(response.get("stdout") or response.get("stderr")),
        response_status_hint=response.get("status_hint"),
        stdout_preview=(stdout or b"").decode("utf-8", errors="replace")[:2000],
        stderr_preview=((stderr or b"").decode("utf-8", errors="replace") + "\n" + str(response.get("stderr") or ""))[:4000],
        exit_code=final_code,
        diagnosis=diagnosis if final_code in (None, 0) or request_sent else f"backend_exit_{final_code}",
    )
    output = result.to_dict()
    output["fastcgi_stdout"] = response.get("stdout", "")[:4000]
    output["socket_path"] = str(socket_path)
    output["duration"] = round(time.monotonic() - start, 3)
    return output


def _blocked_result(diagnosis: str, reason: str, *, socket_path: str) -> dict[str, Any]:
    result = FastCGIHarnessResult(
        backend_started=False,
        backend_alive=False,
        socket_ready=False,
        request_sent=False,
        response_received=False,
        response_status_hint=None,
        stdout_preview="",
        stderr_preview=reason,
        exit_code=None,
        diagnosis=diagnosis,
    ).to_dict()
    result["success"] = False
    result["runtime_environment_blocked"] = True
    result["blocked_reason"] = reason
    result["socket_path"] = socket_path
    result["fastcgi_stdout"] = ""
    result["duration"] = 0.0
    return result


def default_fastcgi_params() -> dict[str, str]:
    return {
        "FCGI_ROLE": "RESPONDER",
        "REQUEST_METHOD": "GET",
        "REQUEST_URI": "/services/device_manager/",
        "SCRIPT_NAME": "/services/device_manager/",
        "PATH_INFO": "",
        "QUERY_STRING": "",
        "CONTENT_LENGTH": "0",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "SERVER_NAME": "127.0.0.1",
        "SERVER_PORT": "3000",
        "REMOTE_ADDR": "127.0.0.1",
        "REMOTE_PORT": "12345",
        "DOCUMENT_ROOT": "/www",
    }


def _record(record_type: int, request_id: int, content: bytes) -> bytes:
    padding_length = (8 - (len(content) % 8)) % 8
    header = struct.pack("!BBHHBB", FCGI_VERSION, record_type, request_id, len(content), padding_length, 0)
    return header + content + (b"\x00" * padding_length)


def _name_value(name: str, value: str) -> bytes:
    encoded_name = name.encode("utf-8")
    encoded_value = value.encode("utf-8")
    return _length(len(encoded_name)) + _length(len(encoded_value)) + encoded_name + encoded_value


def _length(value: int) -> bytes:
    if value < 128:
        return bytes([value])
    return struct.pack("!I", value | 0x80000000)


def _status_hint(stdout_text: str) -> int | None:
    for line in stdout_text.splitlines()[:10]:
        if line.lower().startswith("status:"):
            parts = line.split(":", 1)[1].strip().split()
            if parts and parts[0].isdigit():
                return int(parts[0])
    return 200 if stdout_text else None


def _terminate_process(process: subprocess.Popen) -> None:
    if os.name != "nt":
        try:
            os.killpg(process.pid, signal.SIGTERM)
            return
        except OSError:
            pass
    process.terminate()


def _kill_process(process: subprocess.Popen) -> None:
    if os.name != "nt":
        try:
            os.killpg(process.pid, signal.SIGKILL)
            return
        except OSError:
            pass
    process.kill()
