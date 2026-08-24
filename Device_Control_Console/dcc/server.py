"""Local HTTP console: a JSON API plus the single-page UI in ``dcc/web``.

Bound to 127.0.0.1 only, gated by a per-run token, and the ``Host`` header is
checked so a hostile page cannot reach it by DNS rebinding.  No third-party
packages, no outbound calls except the explicit hardware-ID download.
"""

from __future__ import annotations

import csv
import io
import json
import mimetypes
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import actions, hwids, model, pnputil

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]"}

CACHE = model.SnapshotCache()
TOKEN = secrets.token_urlsafe(24)

#: Set when the page asks to hand over to an elevated instance of itself.
_RESTART_ELEVATED = threading.Event()
#: Lets the page tell "UAC declined" apart from "the new instance is still
#: coming up" -- both look like a dead port from the browser's side.
_ELEVATION = {"attempted": False, "declined": False}


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _snapshot(refresh: bool = False):
    return CACHE.get(refresh=refresh)


# --------------------------------------------------------------------------
# API handlers
# --------------------------------------------------------------------------
def api_snapshot(query: dict) -> dict:
    snap = _snapshot(refresh=query.get("refresh") == ["1"])
    return {
        "meta": {
            **snap.meta,
            "elevated": actions.is_elevated(),
            "hwids": hwids.status(),
        },
        "devices": snap.devices,
        "drivers": snap.drivers,
    }


def api_device(query: dict) -> dict:
    ids = query.get("id") or []
    if not ids:
        raise ApiError("missing id")
    instance_id = ids[0]
    snap = _snapshot()
    summary = snap.device_index.get(instance_id)
    if summary is None:
        raise ApiError(f"unknown device {instance_id!r}", 404)
    detail = model.device_detail(instance_id)
    children = [
        {
            "instance_id": c,
            "resolved_name": snap.device_index.get(c, {}).get("resolved_name", ""),
            "description": snap.device_index.get(c, {}).get("description", ""),
            "status": snap.device_index.get(c, {}).get("status", ""),
            "device_type": snap.device_index.get(c, {}).get("device_type", ""),
        }
        for c in summary.get("children") or []
    ]
    related = [
        {
            "instance_id": r,
            "resolved_name": snap.device_index.get(r, {}).get("resolved_name", ""),
            "status": snap.device_index.get(r, {}).get("status", ""),
            "device_type": snap.device_index.get(r, {}).get("device_type", ""),
        }
        for r in summary.get("related") or []
    ]
    parent = summary.get("parent")
    parent_info = None
    if parent and parent in snap.device_index:
        p = snap.device_index[parent]
        parent_info = {
            "instance_id": parent,
            "resolved_name": p.get("resolved_name", ""),
            "status": p.get("status", ""),
        }
    drivers = []
    for name in [summary.get("driver_name")] + list(summary.get("extension_drivers") or []):
        if not name:
            continue
        pkg = snap.driver_index.get(name.lower())
        drivers.append(
            {
                "driver_name": name,
                "in_store": pkg is not None,
                "original_name": (pkg or {}).get("original_name", ""),
                "provider_name": (pkg or {}).get("provider_name", ""),
                "driver_version": (pkg or {}).get("driver_version", ""),
                "signer_name": (pkg or {}).get("signer_name", ""),
                "device_count": (pkg or {}).get("device_count", 0),
                "is_extension": name != summary.get("driver_name"),
            }
        )
    return {
        "summary": summary,
        "properties": {k: v for k, v in detail.items() if not k.startswith("_")},
        "parent": parent_info,
        "children": children,
        "related": related,
        "drivers": drivers,
    }


def api_driver(query: dict) -> dict:
    names = query.get("name") or []
    if not names:
        raise ApiError("missing name")
    snap = _snapshot()
    pkg = snap.driver_index.get(names[0].lower())
    if pkg is None:
        raise ApiError(f"unknown driver package {names[0]!r}", 404)
    devices = [
        snap.device_index.get(i, {"instance_id": i, "resolved_name": "", "status": "Unknown"})
        for i in pkg["device_ids"]
    ]
    return {
        "driver": pkg,
        "devices": [
            {
                "instance_id": d.get("instance_id", ""),
                "resolved_name": d.get("resolved_name", ""),
                "description": d.get("description", ""),
                "device_type": d.get("device_type", ""),
                "status": d.get("status", ""),
                "class_name": d.get("class_name", ""),
                "is_extension_use": pkg["driver_name"] in (d.get("extension_drivers") or []),
            }
            for d in devices
        ],
    }


def api_action(payload: dict) -> dict:
    verb = (payload.get("verb") or "").strip()
    snap = _snapshot()
    known = set(snap.device_index)
    try:
        if verb == "delete-driver":
            names = payload.get("driver_names")
            if not names:
                single = payload.get("driver_name", "")
                names = [single] if single else []
            result = actions.delete_drivers(
                list(names),
                uninstall=bool(payload.get("uninstall")),
                force=bool(payload.get("force")),
                reboot=bool(payload.get("reboot")),
            )
        elif verb == "export-driver":
            result = actions.export_driver(
                payload.get("driver_name", ""), payload.get("target_dir", "")
            )
        elif verb == "add-driver":
            result = actions.add_driver(
                payload.get("inf_path", ""),
                subdirs=bool(payload.get("subdirs")),
                install=bool(payload.get("install")),
            )
        elif verb in actions.SAFE_DEVICE_VERBS:
            result = actions.device_action(
                verb,
                payload.get("instance_id", ""),
                known=known,
                subtree=bool(payload.get("subtree")),
            )
        elif verb == "scan-devices":
            result = actions.scan_devices()
        else:
            raise ApiError(f"unsupported action {verb!r}")
    except actions.ActionError as exc:
        raise ApiError(str(exc)) from exc
    except pnputil.PnpUtilError as exc:
        raise ApiError(str(exc), 500) from exc
    CACHE.invalidate()
    return result


def api_hwids_update(payload: dict) -> dict:
    names = payload.get("tables") or None
    result = hwids.update(names)
    CACHE.invalidate()
    return {"results": result, "status": hwids.status()}


DEVICE_COLUMNS = [
    ("instance_id", "Instance ID"),
    ("resolved_name", "Resolved Device"),
    ("device_type", "Type"),
    ("description", "Device Description"),
    ("class_name", "Class Name"),
    ("class_guid", "Class GUID"),
    ("manufacturer", "Manufacturer Name"),
    ("vendor", "Resolved Vendor"),
    ("status", "Status"),
    ("problem_text", "Problem"),
    ("driver_name", "Driver Name"),
    ("extension_drivers", "Extension Driver Names"),
    ("service", "Service"),
    ("driver_version", "Driver Version"),
    ("location", "Location"),
    ("last_arrival", "Last Arrival"),
    ("last_removal", "Last Removal"),
    ("resolved_from", "Name Resolved From"),
]

DRIVER_COLUMNS = [
    ("driver_name", "Published Name"),
    ("original_name", "Original Name"),
    ("provider_name", "Provider Name"),
    ("class_name", "Class Name"),
    ("class_guid", "Class GUID"),
    ("driver_version", "Driver Version"),
    ("signer_name", "Signer Name"),
    ("attributes", "Attributes"),
    ("driver_package_id", "Driver Package ID"),
    ("family_id", "Family ID"),
    ("device_count", "Devices Using"),
    ("present_device_count", "Connected Devices"),
    ("orphaned", "Orphaned"),
    ("superseded_by", "Superseded By"),
    ("device_names", "Device Names"),
]


def api_export(query: dict) -> tuple[bytes, str, str]:
    what = (query.get("what") or ["devices"])[0]
    fmt = (query.get("format") or ["csv"])[0]
    snap = _snapshot()
    rows = snap.devices if what == "devices" else snap.drivers
    columns = DEVICE_COLUMNS if what == "devices" else DRIVER_COLUMNS
    if fmt == "json":
        body = json.dumps(rows, indent=2, default=str).encode("utf-8")
        return body, "application/json", f"{what}.json"
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerow([label for _key, label in columns])
    for row in rows:
        out = []
        for key, _label in columns:
            value = row.get(key, "")
            if isinstance(value, list):
                value = "; ".join(str(v) for v in value)
            elif isinstance(value, bool):
                value = "yes" if value else "no"
            out.append(value)
        writer.writerow(out)
    return buf.getvalue().encode("utf-8-sig"), "text/csv", f"{what}.csv"


# --------------------------------------------------------------------------
# HTTP plumbing
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "DeviceControlConsole"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quieter console
        if self.server.verbose:  # type: ignore[attr-defined]
            super().log_message(fmt, *args)

    # -- helpers ---------------------------------------------------------
    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
        return host in ALLOWED_HOSTS

    def _token_ok(self, query: dict) -> bool:
        header = self.headers.get("X-DCC-Token")
        if header and secrets.compare_digest(header, TOKEN):
            return True
        given = (query.get("token") or [""])[0]
        return bool(given) and secrets.compare_digest(given, TOKEN)

    def _send(self, status: int, body: bytes, content_type: str,
              extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, status: int = 200) -> None:
        self._send(status, json.dumps(obj, default=str).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _error(self, message: str, status: int = 400) -> None:
        self._json({"error": message}, status)

    # -- routing ---------------------------------------------------------
    def do_GET(self):  # noqa: N802
        if not self._host_ok():
            return self._error("bad host", 403)
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        try:
            if path in ("/", "/index.html"):
                return self._serve_index()
            if path.startswith("/static/"):
                return self._serve_static(path[len("/static/"):])
            if path.startswith("/api/"):
                if not self._token_ok(query):
                    return self._error("bad or missing token", 403)
                if path == "/api/snapshot":
                    return self._json(api_snapshot(query))
                if path == "/api/device":
                    return self._json(api_device(query))
                if path == "/api/driver":
                    return self._json(api_driver(query))
                if path == "/api/hwids":
                    return self._json(hwids.status())
                if path == "/api/ping":
                    return self._json({
                        "ok": True,
                        "elevated": actions.is_elevated(),
                        "pid": os.getpid(),
                        "elevation_declined": _ELEVATION["declined"],
                    })
                if path == "/api/export":
                    body, ctype, filename = api_export(query)
                    return self._send(
                        200, body, ctype,
                        {"Content-Disposition": f'attachment; filename="{filename}"'},
                    )
                return self._error("unknown endpoint", 404)
            return self._error("not found", 404)
        except ApiError as exc:
            return self._error(str(exc), exc.status)
        except Exception as exc:  # surfaced in the UI rather than swallowed
            return self._error(f"{type(exc).__name__}: {exc}", 500)

    def do_HEAD(self):  # noqa: N802
        self.do_GET()

    def do_POST(self):  # noqa: N802
        if not self._host_ok():
            return self._error("bad host", 403)
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if not self._token_ok(query):
            return self._error("bad or missing token", 403)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except ValueError:
            return self._error("body is not valid JSON")
        try:
            if parsed.path == "/api/action":
                return self._json(api_action(payload))
            if parsed.path == "/api/hwids/update":
                return self._json(api_hwids_update(payload))
            if parsed.path == "/api/refresh":
                CACHE.invalidate()
                return self._json({"ok": True})
            if parsed.path == "/api/relaunch-admin":
                if actions.is_elevated():
                    return self._json({"ok": True, "already": True})
                _ELEVATION["attempted"] = True
                _ELEVATION["declined"] = False
                _RESTART_ELEVATED.set()
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return self._json({"ok": True, "already": False})
            if parsed.path == "/api/shutdown":
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return self._json({"ok": True})
            return self._error("unknown endpoint", 404)
        except ApiError as exc:
            return self._error(str(exc), exc.status)
        except Exception as exc:
            return self._error(f"{type(exc).__name__}: {exc}", 500)

    # -- static ----------------------------------------------------------
    def _serve_index(self) -> None:
        with open(os.path.join(WEB_DIR, "index.html"), "r", encoding="utf-8") as fh:
            html = fh.read()
        html = html.replace("__DCC_TOKEN__", TOKEN)
        self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")

    def _serve_static(self, name: str) -> None:
        safe = os.path.normpath(name).replace("\\", "/")
        if safe.startswith("..") or safe.startswith("/"):
            return self._error("forbidden", 403)
        full = os.path.join(WEB_DIR, safe)
        if not os.path.isfile(full):
            return self._error("not found", 404)
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        with open(full, "rb") as fh:
            body = fh.read()
        self._send(200, body, ctype)


class Server(ThreadingHTTPServer):
    #: On Windows SO_REUSEADDR lets a second socket steal a live port, which
    #: would silently split traffic between the old and new instance.
    allow_reuse_address = False
    daemon_threads = True
    verbose = False


def _bind(host: str, port: int, attempts: int = 40, delay: float = 0.4) -> Server:
    """Bind, retrying while a previous instance finishes releasing the port."""
    last: OSError | None = None
    for _ in range(attempts):
        try:
            return Server((host, port), Handler)
        except OSError as exc:
            last = exc
            time.sleep(delay)
    raise SystemExit(f"could not bind {host}:{port} -- {last}")


def _port_answers(host: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _wait_for_port(host: str, port: int, timeout: float = 40.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _port_answers(host, port):
            return True
        time.sleep(0.3)
    return False


def _relaunch_command(port: int, token_file: str) -> list[str]:
    """Rebuild this program's own command line for the elevated child."""
    script = os.path.abspath(sys.argv[0]) if sys.argv and sys.argv[0] else ""
    head = [script] if script.lower().endswith(".py") and os.path.isfile(script) else ["-m", "dcc"]
    return [*head, "serve", "--port", str(port), "--no-browser", "--token-file", token_file]


def _spawn_elevated(host: str, port: int, token: str) -> bool:
    """Start an elevated copy of the console on the same port and token.

    The token travels through a short-lived file rather than the command line,
    so it never shows up in the process list.
    """
    fd, token_file = tempfile.mkstemp(prefix="dcc_tok_", suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(token)
    args = _relaunch_command(port, token_file)
    quoted = ",".join("'" + a.replace("'", "''") + "'" for a in args)
    ps = (
        f"try {{ Start-Process -FilePath '{sys.executable}' "
        f"-ArgumentList {quoted} -Verb RunAs -WorkingDirectory "
        f"'{os.path.abspath(os.getcwd())}' -WindowStyle Hidden; exit 0 }} "
        "catch { exit 1 }"
    )
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=180,
            creationflags=pnputil.CREATE_NO_WINDOW,
        )
        started = proc.returncode == 0
    except Exception:
        started = False
    if not started:
        try:
            os.remove(token_file)
        except OSError:
            pass
    return started


def serve(host: str = "127.0.0.1", port: int = 8777, open_browser: bool = True,
          verbose: bool = False, prewarm: bool = True, token: str | None = None) -> None:
    global TOKEN
    if token:
        TOKEN = token
    url = f"http://{host}:{port}/?token={TOKEN}"
    print("Device Control Console")
    print(f"  URL         : {url}")
    print(f"  Elevated    : {'yes' if actions.is_elevated() else 'no (write actions will prompt for UAC)'}")
    print("  Stop        : Ctrl+C", flush=True)
    if prewarm:
        threading.Thread(target=lambda: CACHE.get(refresh=True), daemon=True).start()
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()

    while True:
        httpd = _bind(host, port)
        httpd.verbose = verbose
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nstopping...")
            httpd.server_close()
            return
        httpd.server_close()

        if not _RESTART_ELEVATED.is_set():
            return
        _RESTART_ELEVATED.clear()
        print("  handing over to an elevated instance...", flush=True)
        if _spawn_elevated(host, port, TOKEN) and _wait_for_port(host, port):
            print("  elevated instance is serving; this one is done.", flush=True)
            return
        # UAC was declined, or the child never came up: take the port back so
        # the page the user is looking at keeps working.
        _ELEVATION["declined"] = True
        print("  elevation did not complete; continuing as standard user.", flush=True)
