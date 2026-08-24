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


_ITEM_MARK = "__DCC_ITEM__"


def _write_batch_script(commands: list[list[str]], out_path: str) -> str:
    """A .cmd that runs each pnputil call and records its own exit code.

    Passing the whole pipeline as one argument to ``cmd /c`` does not survive
    cmd's quote-stripping rule -- a string that begins with a quote and
    contains several more comes back as "The filename, directory name, or
    volume label syntax is incorrect". A script file has no such rule, and it
    lets a batch of deletions run behind a single UAC prompt instead of one
    prompt per package.
    """
    fd, script = tempfile.mkstemp(suffix=".cmd", prefix="dcc_run_")
    os.close(fd)
    lines = ["@echo off"]
    for index, args in enumerate(commands):
        rendered = " ".join(_quote(a) for a in args)
        lines.append(f"echo.>> {_quote(out_path)}")
        lines.append(f"{_quote(pnputil.PNPUTIL)} {rendered} >> {_quote(out_path)} 2>&1")
        # %ERRORLEVEL% expands as each line is read, so this captures the call
        # immediately above it.
        lines.append(f"echo {_ITEM_MARK}{index}:%ERRORLEVEL%>> {_quote(out_path)}")
    with open(script, "w", encoding="ascii", errors="replace", newline="\r\n") as fh:
        fh.write("\n".join(lines) + "\n")
    return script


def _parse_batch_output(text: str, commands: list[list[str]]) -> list[dict]:
    """Split the shared output file back into one result per command."""
    results = []
    positions = [(m.start(), int(m.group(1)), int(m.group(2)))
                 for m in re.finditer(_ITEM_MARK + r"(\d+):(-?\d+)", text)]
    codes = {index: code for _pos, index, code in positions}
    chunks = {}
    cursor = 0
    for pos, index, _code in positions:
        chunks[index] = text[cursor:pos]
        cursor = text.index("\n", pos) + 1 if "\n" in text[pos:] else len(text)
    for index, args in enumerate(commands):
        code = codes.get(index, -1)
        body = chunks.get(index, "")
        for mark in re.findall(_ITEM_MARK + r"\d+:-?\d+", body):
            body = body.replace(mark, "")
        results.append({
            "command": "pnputil " + " ".join(args),
            "returncode": code,
            "ok": code in (0, 3010),
            "reboot_required": code == 3010,
            "output": body.strip() or ("(no output)" if code != -1 else "did not run"),
        })
    return results


def run_elevated(commands: list[list[str]], timeout: int = 900) -> list[dict]:
    """Run one or more pnputil calls through a single UAC prompt."""
    fd, out_path = tempfile.mkstemp(suffix=".txt", prefix="dcc_elev_")
    os.close(fd)
    script = _write_batch_script(commands, out_path)
    ps = (
        "Start-Process -FilePath cmd.exe -ArgumentList '/c', "
        + _powershell_literal(f'"{script}"')
        + " -Verb RunAs -Wait -WindowStyle Hidden; exit 0"
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

        if _ITEM_MARK not in text:
            # Nothing ran: almost always a declined UAC prompt.
            reason = (proc.stderr or "").strip() or "Elevation was cancelled."
            return [{
                "command": "pnputil " + " ".join(args),
                "returncode": 1223,
                "ok": False,
                "reboot_required": False,
                "output": reason,
            } for args in commands]

        results = _parse_batch_output(text, commands)
        for r in results:
            r["elevated"] = True
        return results
    finally:
        for path in (out_path, script):
            try:
                os.remove(path)
            except OSError:
                pass


def _powershell_literal(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def _dispatch_many(commands: list[list[str]]) -> list[dict]:
    """Run a batch, elevating once for the whole thing when needed."""
    if not commands:
        return []
    if is_elevated():
        results = []
        for args in commands:
            result = pnputil._action(args)
            result["elevated"] = True
            results.append(result)
        return results
    return run_elevated(commands)


def _dispatch(args: list[str]) -> dict:
    return _dispatch_many([args])[0]


# --------------------------------------------------------------------------
# public verbs
# --------------------------------------------------------------------------
def _delete_args(name: str, uninstall: bool, force: bool, reboot: bool) -> list[str]:
    args = ["/delete-driver", name]
    if uninstall:
        args.append("/uninstall")
    if force:
        args.append("/force")
    if reboot:
        args.append("/reboot")
    return args


def delete_driver(oem_inf: str, uninstall: bool = False, force: bool = False,
                  reboot: bool = False) -> dict:
    name = validate_oem_inf(oem_inf)
    return _dispatch(_delete_args(name, uninstall, force, reboot))


def delete_drivers(oem_infs: list[str], uninstall: bool = False, force: bool = False,
                   reboot: bool = False) -> dict:
    """Delete several packages behind one UAC prompt.

    Every name is validated before anything runs, so a single bad entry cannot
    result in half a batch being deleted.
    """
    names = [validate_oem_inf(n) for n in oem_infs]
    if not names:
        raise ActionError("no driver packages given")
    commands = [_delete_args(n, uninstall, force, reboot) for n in names]
    results = _dispatch_many(commands)
    for name, result in zip(names, results):
        result["driver_name"] = name
    succeeded = [r for r in results if r["ok"]]
    failed = [r for r in results if not r["ok"]]
    return {
        "verb": "delete-driver",
        "count": len(names),
        "succeeded": len(succeeded),
        "failed": len(failed),
        "ok": not failed,
        "reboot_required": any(r["reboot_required"] for r in results),
        "elevated": True,
        "results": results,
        "command": f"pnputil /delete-driver x{len(names)}",
        "output": "\n".join(
            f"{r['driver_name']}: exit {r['returncode']}"
            + ("" if r["ok"] else f" -- {r['output'].splitlines()[0] if r['output'] else ''}")
            for r in results
        ),
    }


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
