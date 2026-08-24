"""Command line for Device Control Console -- everything the UI does, scriptable."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys

from . import actions, hwids, model, server
from .resolve import Resolver


# --------------------------------------------------------------------------
# output helpers
# --------------------------------------------------------------------------
def _w(text: str = "") -> None:
    sys.stdout.write(text + "\n")


def print_table(rows: list[dict], columns: list[tuple[str, str]], limit: int = 0) -> None:
    if not rows:
        _w("(no matching rows)")
        return
    shown = rows[:limit] if limit else rows
    cells = [[_cell(r.get(k)) for k, _ in columns] for r in shown]
    widths = [len(label) for _, label in columns]
    for row in cells:
        for i, value in enumerate(row):
            widths[i] = max(widths[i], len(value))
    widths = [min(w, 58) for w in widths]

    def line(values):
        return "  ".join(v[: widths[i]].ljust(widths[i]) for i, v in enumerate(values))

    _w(line([label for _, label in columns]))
    _w("  ".join("-" * w for w in widths))
    for row in cells:
        _w(line(row))
    if limit and len(rows) > limit:
        _w(f"... {len(rows) - limit} more (use --limit 0 to show all)")


def _cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)


def write_csv(path: str, rows: list[dict], columns: list[tuple[str, str]]) -> None:
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow([label for _, label in columns])
        for row in rows:
            writer.writerow([_cell(row.get(k)) for k, _ in columns])
    _w(f"wrote {len(rows)} rows to {path}")


DEVICE_COLUMNS = [
    ("device_type", "TYPE"),
    ("resolved_name", "RESOLVED DEVICE"),
    ("instance_id", "INSTANCE ID"),
    ("status", "STATUS"),
    ("driver_name", "DRIVER"),
]
DRIVER_COLUMNS = [
    ("driver_name", "PUBLISHED"),
    ("original_name", "ORIGINAL"),
    ("provider_name", "PROVIDER"),
    ("class_name", "CLASS"),
    ("driver_version", "VERSION"),
    ("device_count", "DEVICES"),
    ("superseded_by", "SUPERSEDED BY"),
]


def _match(row: dict, needle: str) -> bool:
    if not needle:
        return True
    blob = row.get("search_blob") or ""
    return all(term in blob for term in needle.lower().split())


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def cmd_serve(args) -> int:
    token = None
    if args.token_file:
        # Written by the instance that asked for elevation; read once, then gone.
        try:
            with open(args.token_file, "r", encoding="utf-8") as fh:
                token = fh.read().strip() or None
        except OSError:
            token = None
        finally:
            try:
                os.remove(args.token_file)
            except OSError:
                pass
    server.serve(port=args.port, open_browser=not args.no_browser,
                 verbose=args.verbose, token=token)
    return 0


def cmd_devices(args) -> int:
    snap = model.build()
    rows = [d for d in snap.devices if _match(d, args.search or "")]
    if args.status == "connected":
        rows = [d for d in rows if d["present"]]
    elif args.status == "disconnected":
        rows = [d for d in rows if not d["present"]]
    elif args.status == "problem":
        rows = [d for d in rows if d["problem_code"]]
    if args.klass:
        rows = [d for d in rows if d["class_name"].lower() == args.klass.lower()]
    if args.type:
        rows = [d for d in rows if args.type.lower() in (d["device_type"] or "").lower()]
    rows.sort(key=lambda d: str(d.get(args.sort, "")).lower())
    if args.json:
        _w(json.dumps(rows, indent=2, default=str))
    elif args.csv:
        write_csv(args.csv, rows, [(k, k) for k in rows[0]] if rows else DEVICE_COLUMNS)
    else:
        print_table(rows, DEVICE_COLUMNS, args.limit)
        _w(f"\n{len(rows)} device(s) of {snap.meta['device_count']}")
    return 0


def cmd_drivers(args) -> int:
    snap = model.build()
    rows = [d for d in snap.drivers if _match(d, args.search or "")]
    if args.state == "orphaned":
        rows = [d for d in rows if d["orphaned"]]
    elif args.state == "inuse":
        rows = [d for d in rows if not d["orphaned"]]
    elif args.state == "superseded":
        rows = [d for d in rows if d["superseded_by"]]
    elif args.state == "extension":
        rows = [d for d in rows if d["is_extension"]]
    if args.klass:
        rows = [d for d in rows if d["class_name"].lower() == args.klass.lower()]
    rows.sort(key=lambda d: str(d.get(args.sort, "")).lower())
    if args.json:
        _w(json.dumps(rows, indent=2, default=str))
    elif args.csv:
        write_csv(args.csv, rows, [(k, k) for k in rows[0]] if rows else DRIVER_COLUMNS)
    else:
        print_table(rows, DRIVER_COLUMNS, args.limit)
        _w(f"\n{len(rows)} package(s) of {snap.meta['driver_count']} "
           f"({snap.meta['orphan_driver_count']} orphaned, "
           f"{snap.meta['superseded_driver_count']} superseded)")
    return 0


def cmd_resolve(args) -> int:
    """Print the pnputil block for a device, with the resolved name added."""
    snap = model.build()
    needle = args.query.lower()
    exact = [d for d in snap.devices if d["instance_id"].lower() == needle]
    rows = exact or [d for d in snap.devices if _match(d, needle)]
    if not rows:
        _w(f"no device matches {args.query!r}")
        return 1
    resolver = Resolver(snap.device_index)
    for dev in rows[: args.limit or len(rows)]:
        _w("")
        _w(f"Instance ID:                {dev['instance_id']}")
        _w(f"  >> Resolved device:       {dev['resolved_name']}"
           f"  [{dev['resolved_confidence']} confidence]")
        _w(f"  >> via:                   {dev['resolved_from']}")
        _w(f"  >> Type:                  {dev['device_type']}  ({dev['type_from']})")
        _w(f"  >> Vendor:                {dev['vendor']}")
        _w(f"Device Description:         {dev['description']}")
        _w(f"Class Name:                 {dev['class_name']}")
        _w(f"Class GUID:                 {dev['class_guid']}")
        _w(f"Manufacturer Name:          {dev['manufacturer']}")
        _w(f"Status:                     {dev['status']}"
           + (f"  (problem {dev['problem_code']}: {dev['problem_text']})" if dev["problem_code"] else ""))
        if dev.get("driver_name"):
            _w(f"Driver Name:                {dev['driver_name']}")
        if dev.get("extension_drivers"):
            _w(f"Extension Driver Names:     {', '.join(dev['extension_drivers'])}")
        if args.relations:
            children = resolver.children_of(dev["instance_id"])
            if children:
                _w("Children:")
                for c in children:
                    kid = snap.device_index.get(c, {})
                    _w(f"    {kid.get('resolved_name', '?'):<44} {c}")
            related = resolver.relatives(dev["instance_id"])
            if related:
                _w("Related hardware:")
                for r in related[:12]:
                    rel = snap.device_index.get(r, {})
                    _w(f"    {rel.get('resolved_name', '?'):<44} {r}")
    _w("")
    if len(rows) > (args.limit or len(rows)):
        _w(f"({len(rows)} matches, showing {args.limit})")
    return 0


def cmd_orphans(args) -> int:
    snap = model.build()
    rows = [d for d in snap.drivers if d["orphaned"] or (args.superseded and d["superseded_by"])]
    print_table(rows, DRIVER_COLUMNS, args.limit)
    total = sum(1 for d in snap.drivers if d["orphaned"])
    _w(f"\n{len(rows)} candidate(s); {total} package(s) have no device attached.")
    _w("Delete one with:  dcc delete-driver oem42.inf")
    return 0


def cmd_delete_driver(args) -> int:
    snap = model.build()
    pkg = snap.driver_index.get(args.name.lower())
    if pkg is None:
        _w(f"{args.name} is not in the driver store")
        return 1
    _w(f"{pkg['driver_name']}  {pkg['original_name']}  ({pkg['provider_name']}, "
       f"{pkg['driver_version']}) -- used by {pkg['device_count']} device(s)")
    if not args.yes:
        answer = input("Delete this package from the driver store? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            _w("aborted")
            return 1
    result = actions.delete_driver(
        args.name, uninstall=args.uninstall, force=args.force, reboot=args.reboot
    )
    _w(result["output"])
    _w(f"exit {result['returncode']}" + (" (reboot required)" if result["reboot_required"] else ""))
    return 0 if result["ok"] else 2


def cmd_device_action(args) -> int:
    snap = model.build()
    result = actions.device_action(
        args.verb, args.instance_id, known=set(snap.device_index),
        subtree=getattr(args, "subtree", False)
    )
    _w(result["output"])
    return 0 if result["ok"] else 2


def cmd_tree(args) -> int:
    snap = model.build()
    resolver = Resolver(snap.device_index)
    roots = [d for d in snap.devices if not d["parent"] or d["parent"] not in snap.device_index]

    def walk(dev, depth):
        if depth > args.depth:
            return
        pad = "  " * depth
        flag = "" if dev["present"] else "  [disconnected]"
        _w(f"{pad}{dev['resolved_name']}  ({dev['device_type']}){flag}")
        _w(f"{pad}   {dev['instance_id']}")
        for child in sorted(resolver.children_of(dev["instance_id"])):
            kid = snap.device_index.get(child)
            if kid:
                walk(kid, depth + 1)

    for root in sorted(roots, key=lambda d: d["resolved_name"].lower()):
        walk(root, 0)
    return 0


def cmd_update_hwids(args) -> int:
    _w("downloading usb.ids and pci.ids ...")
    for name, result in hwids.update().items():
        if result.get("ok"):
            _w(f"  {name}: {result['bytes']} bytes, {result['vendors']} vendors")
        else:
            _w(f"  {name}: FAILED -- {result.get('error')}")
    return 0


def cmd_status(args) -> int:
    snap = model.build()
    _w(json.dumps({**snap.meta, "elevated": actions.is_elevated(),
                   "hwids": hwids.status()}, indent=2, default=str))
    return 0


# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dcc",
        description="Device Control Console -- manage the Windows driver store and devices.",
    )
    sub = p.add_subparsers(dest="command", required=False)

    s = sub.add_parser("serve", help="run the local web console (default)")
    s.add_argument("--port", type=int, default=8777)
    s.add_argument("--no-browser", action="store_true")
    s.add_argument("--verbose", action="store_true")
    s.add_argument("--token-file", default="",
                   help="read the session token from this file, then delete it "
                        "(used when handing over to an elevated instance)")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("devices", help="list devices with resolved names")
    s.add_argument("search", nargs="?", default="")
    s.add_argument("--status", choices=["all", "connected", "disconnected", "problem"], default="all")
    s.add_argument("--class", dest="klass", default="")
    s.add_argument("--type", default="")
    s.add_argument("--sort", default="resolved_name")
    s.add_argument("--limit", type=int, default=60)
    s.add_argument("--json", action="store_true")
    s.add_argument("--csv", default="")
    s.set_defaults(func=cmd_devices)

    s = sub.add_parser("drivers", help="list driver-store packages")
    s.add_argument("search", nargs="?", default="")
    s.add_argument("--state", choices=["all", "inuse", "orphaned", "superseded", "extension"],
                   default="all")
    s.add_argument("--class", dest="klass", default="")
    s.add_argument("--sort", default="driver_name")
    s.add_argument("--limit", type=int, default=60)
    s.add_argument("--json", action="store_true")
    s.add_argument("--csv", default="")
    s.set_defaults(func=cmd_drivers)

    s = sub.add_parser("resolve", help="resolve an instance ID to the real device")
    s.add_argument("query")
    s.add_argument("--relations", action="store_true", help="also print children and related hardware")
    s.add_argument("--limit", type=int, default=5)
    s.set_defaults(func=cmd_resolve)

    s = sub.add_parser("orphans", help="driver packages no device is using")
    s.add_argument("--superseded", action="store_true", help="include older versions still in the store")
    s.add_argument("--limit", type=int, default=0)
    s.set_defaults(func=cmd_orphans)

    s = sub.add_parser("delete-driver", help="delete a package from the driver store")
    s.add_argument("name")
    s.add_argument("--uninstall", action="store_true")
    s.add_argument("--force", action="store_true")
    s.add_argument("--reboot", action="store_true")
    s.add_argument("-y", "--yes", action="store_true", help="do not prompt")
    s.set_defaults(func=cmd_delete_driver)

    for verb in ("enable-device", "disable-device", "restart-device", "remove-device"):
        s = sub.add_parser(verb, help=f"pnputil /{verb}")
        s.add_argument("instance_id")
        if verb == "remove-device":
            s.add_argument("--subtree", action="store_true")
        s.set_defaults(func=cmd_device_action, verb=verb)

    s = sub.add_parser("tree", help="print the device tree with resolved names")
    s.add_argument("--depth", type=int, default=4)
    s.set_defaults(func=cmd_tree)

    s = sub.add_parser("update-hwids", help="download usb.ids / pci.ids for offline name resolution")
    s.set_defaults(func=cmd_update_hwids)

    s = sub.add_parser("status", help="print a JSON summary of the machine")
    s.set_defaults(func=cmd_status)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        args = parser.parse_args(["serve", *(argv or [])])
    try:
        return args.func(args)
    except actions.ActionError as exc:
        _w(f"error: {exc}")
        return 2
    except KeyboardInterrupt:
        return 130
