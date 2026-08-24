"""Write operations, elevation, and the guard rails around them.

Every pnputil verb that changes the machine needs administrator rights.  When
the console is not elevated the command is re-launched through UAC and its
output captured, so the UI still shows what happened.

Nothing here interpolates untrusted text into a command line: instance IDs must
match a device in the current snapshot, INF names must match ``oem<n>.inf``, and
paths are resolved and existence-checked before use.
"""

from __future__ import annotations

import ctypes
import os
import re
import subprocess
import tempfile

from . import pnputil

OEM_INF_RE = re.compile(r"^oem\d+\.inf$", re.IGNORECASE)
INSTANCE_ID_RE = re.compile(r"^[A-Za-z0-9_\-.\\{}&#+ ]{3,400}$")

#: verb -> (pnputil args builder, needs elevation)
SAFE_DEVICE_VERBS = {"enable-device", "disable-device", "restart-device", "remove-device"}


class ActionError(ValueError):
    """Raised when a request fails validation -- never reaches pnputil."""


def is_elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def validate_oem_inf(name: str) -> str:
    name = (name or "").strip()
    if not OEM_INF_RE.match(name):
        raise ActionError(
            f"{name!r} is not a driver-store package name; expected e.g. oem42.inf"
        )
    return name.lower()


def validate_instance_id(instance_id: str, known: set[str] | None = None) -> str:
    instance_id = (instance_id or "").strip()
    if not INSTANCE_ID_RE.match(instance_id):
        raise ActionError(f"{instance_id!r} is not a valid device instance ID")
    if known is not None and instance_id not in known:
        raise ActionError(
            f"{instance_id!r} is not in the current snapshot; refresh and retry"
        )
    return instance_id


def validate_directory(path: str) -> str:
    path = os.path.abspath(os.path.expandvars(os.path.expanduser((path or "").strip())))
    if not os.path.isdir(path):
        raise ActionError(f"{path!r} is not an existing directory")
    return path


def _quote(arg: str) -> str:
    return '"' + arg.replace('"', '""') + '"'


def run_elevated(args: list[str], timeout: int = 600) -> dict:
    """Run ``pnputil <args>`` through UAC, capturing output and the exit code."""
    fd, out_path = tempfile.mkstemp(suffix=".txt", prefix="dcc_elev_")
    os.close(fd)
    exe = pnputil.PNPUTIL
    cmdline = (
        f"{_quote(exe)} " + " ".join(_quote(a) for a in args) +
        f" > {_quote(out_path)} 2>&1 & echo __DCC_EXIT__%ERRORLEVEL% >> {_quote(out_path)}"
    )
    ps = (
        "$p = Start-Process -FilePath cmd.exe -ArgumentList '/c', "
        + _powershell_literal(cmdline)
        + " -Verb RunAs -Wait -WindowStyle Hidden -PassThru; exit 0"
    )
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=pnputil.CREATE_NO_WINDOW,
        )
        try:
            with open(out_path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            text = ""
        code = -1
        m = re.search(r"__DCC_EXIT__(-?\d+)", text)
        if m:
            code = int(m.group(1))
            text = text[: m.start()].rstrip()
        elif proc.returncode != 0 or "canceled" in (proc.stderr or "").lower():
            text = (text + "\n" + (proc.stderr or "")).strip() or "Elevation was cancelled."
        return {
            "command": "pnputil " + " ".join(args),
            "elevated": True,
            "returncode": code,
            "ok": code in (0, 3010),
            "reboot_required": code == 3010,
            "output": text.strip() or "(no output)",
        }
    finally:
        try:
            os.remove(out_path)
        except OSError:
            pass


def _powershell_literal(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def _dispatch(args: list[str]) -> dict:
    if is_elevated():
        result = pnputil._action(args)
        result["elevated"] = True
        return result
    return run_elevated(args)


# --------------------------------------------------------------------------
# public verbs
# --------------------------------------------------------------------------
def delete_driver(oem_inf: str, uninstall: bool = False, force: bool = False,
                  reboot: bool = False) -> dict:
    name = validate_oem_inf(oem_inf)
    args = ["/delete-driver", name]
    if uninstall:
        args.append("/uninstall")
    if force:
        args.append("/force")
    if reboot:
        args.append("/reboot")
    return _dispatch(args)


def export_driver(oem_inf: str, target_dir: str) -> dict:
    name = validate_oem_inf(oem_inf)
    target = validate_directory(target_dir)
    return _dispatch(["/export-driver", name, target])


def add_driver(inf_path: str, subdirs: bool = False, install: bool = False) -> dict:
    path = os.path.abspath(os.path.expandvars(os.path.expanduser((inf_path or "").strip())))
    if not path.lower().endswith(".inf") or not os.path.isfile(path):
        raise ActionError(f"{path!r} is not an existing .inf file")
    args = ["/add-driver", path]
    if subdirs:
        args.append("/subdirs")
    if install:
        args.append("/install")
    return _dispatch(args)


def device_action(verb: str, instance_id: str, known: set[str] | None = None,
                  subtree: bool = False) -> dict:
    if verb not in SAFE_DEVICE_VERBS:
        raise ActionError(f"unsupported device action {verb!r}")
    iid = validate_instance_id(instance_id, known)
    args = [f"/{verb}", iid]
    if verb == "remove-device" and subtree:
        args.append("/subtree")
    return _dispatch(args)


def scan_devices() -> dict:
    return _dispatch(["/scan-devices"])
