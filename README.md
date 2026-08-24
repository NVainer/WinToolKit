# Device Control Console

A local console for the Windows driver store and device tree — the things
`pnputil` can only show you as flat text.

`pnputil /enum-devices` tells you this:

```
Instance ID:                USB\VID_1038&PID_1838\6&2ae87d4e&0&1
Device Description:         USB Composite Device
Class Name:                 USB
Class GUID:                 {36fc9e60-c465-11cf-8056-444553540000}
Manufacturer Name:          (Standard USB Host Controller)
Status:                     Disconnected
Driver Name:                usb.inf
Extension Driver Names:     oem77.inf
```

Which is accurate and useless — you still have to go and look up the VID/PID on
the web to find out what the thing actually is. This console keeps every one of
those fields and adds the answer:

```
Instance ID:                USB\VID_1038&PID_1838\6&2ae87d4e&0&1
  >> Resolved device:       SteelSeries Aerox 3 Wireless  [high confidence]
  >> via:                   BusReportedDeviceDesc
  >> Type:                  Mouse  (HID\VID_1038&PID_1838&MI_00&Col01\... HID usage page)
  >> Vendor:                SteelSeries ApS
Device Description:         USB Composite Device
Class Name:                 USB
Class GUID:                 {36fc9e60-c465-11cf-8056-444553540000}
Manufacturer Name:          (Standard USB Host Controller)
Status:                     Disconnected
Driver Name:                usb.inf
Extension Driver Names:     oem77.inf
```

No web lookup involved — the name was on the machine the whole time, just not
in the field `pnputil` prints.

## Features

- **Name resolution.** Generic descriptions (`USB Composite Device`,
  `Generic PnP Monitor`, `Bluetooth Device`, `USB Input Device`) are resolved to
  the real product, with the source and a confidence level shown so you can tell
  a certainty from a guess.
- **Device type.** `Mouse`, `Keyboard`, `Monitor`, `Network adapter`… inferred
  from HID usage pages and setup classes, including for parent nodes whose own
  class is just `USB`.
- **Driver ↔ device relations, both ways.** Click a device to see its driver
  package, extension drivers, parent, children and sibling functions; click a
  package to see every device using it.
- **Search and sort.** One search box over every field (names, instance IDs,
  VID/PID, INF names, class, vendor, service, status); click any column to sort.
- **Columns you control.** 30 device columns and 18 driver columns to pick from
  (**Columns…**), drag a header edge to resize, double-click that edge to fit the
  content. The layout is remembered per view.
- **Group by.** Type, class, status, manufacturer, vendor, driver package, bus,
  name confidence, connected/disconnected — or **physical device**, which uses
  the Windows container ID to gather every function of one piece of hardware
  under a single heading. Groups collapse individually or all at once.
- **Graph mode.** The device tree as a node-link diagram — pan, zoom, expand a
  branch from its `+n` badge, double-click to re-root, and switch on driver
  packages to see which devices share which `oem*.inf`.
- **Cleanup view.** Orphaned packages nothing uses, superseded older copies of a
  package, devices with problem codes, and leftover disconnected nodes.
- **Full control.** Delete, export and add driver packages; enable, disable,
  restart and remove devices; rescan for hardware changes. Every write goes
  through `pnputil`, and the exact command and its output are shown.
- **Device tree.** The real parent/child tree with resolved names.
- **Export.** Devices or driver store to CSV/JSON, from the UI or the CLI.

## Two builds

The same console ships two ways. Both serve the identical UI — `dcc/web/` is
shared, not duplicated — and produce identical data.

| | Python build | Native build |
| --- | --- | --- |
| Needs | Python 3.10+ | nothing — .NET Framework 4.x is in-box on Win10/11 |
| Ships as | the repo | one ~190 KB `DeviceControlConsole.exe` |
| Start with | `run.cmd` | double-click the exe |
| Full scan | ~1.8 s | ~1.7 s (device enumeration alone: 0.4 s vs 1.8 s) |
| Good for | hacking on it | locked-down machines, USB sticks, PCs without Python |

Neither needs third-party packages: the Python build is standard library only,
and the native build is compiled by the C# compiler that ships inside Windows.

### Building the native exe

```bash
native\build.cmd
```

No SDK, no NuGet, no downloads. It uses
`%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe`, embeds the web UI
as resources, and writes `native\bin\DeviceControlConsole.exe`. Copy that one
file anywhere — it needs nothing beside it.

It runs `asInvoker`, so it never demands a UAC prompt just to look at devices,
and it serves over a plain loopback socket rather than `HttpListener` —
http.sys would otherwise require an admin-registered URL reservation, making
the console admin-only for no reason. The `usb.ids` / `pci.ids` cache is kept
next to the exe when that folder is writable (so a USB copy carries it), and
falls back to `%LOCALAPPDATA%` when it is not.

## Requirements

Windows 10 21H2 / Windows 11 or newer — both builds need `pnputil /format xml`.

## Run

```bash
run.cmd
```

That starts the console on `http://127.0.0.1:8777` and opens a browser. Write
actions raise a UAC prompt when you use them.

To skip the per-action prompts, either start it elevated:

```bash
run-admin.cmd
```

…or click **Open as Admin** in the header. That restarts the console elevated on
the same address and token, so the page you are looking at keeps working — no
new tab, no re-navigating. Decline the UAC prompt and the original console
simply takes its port back and carries on unelevated.

Other options:

```bash
python dcc.py serve --port 9000 --no-browser
```

## Command line

Everything the UI does is scriptable.

```bash
python dcc.py resolve "USB\VID_1038&PID_1838\6&2ae87d4e&0&1" --relations
```

```bash
python dcc.py devices "steelseries" --status disconnected
```

```bash
python dcc.py drivers --state orphaned --limit 0
```

```bash
python dcc.py orphans --superseded
```

```bash
python dcc.py delete-driver oem42.inf --uninstall
```

```bash
python dcc.py tree --depth 3
```

```bash
python dcc.py devices --csv devices.csv
```

| Command | What it does |
| --- | --- |
| `serve` | Run the web console (default when no command is given) |
| `devices [search]` | List devices with resolved names; `--status`, `--class`, `--type`, `--sort`, `--json`, `--csv` |
| `drivers [search]` | List driver-store packages; `--state inuse\|orphaned\|superseded\|extension` |
| `resolve <query>` | Print the pnputil block for a device plus the resolved identity; `--relations` |
| `orphans` | Packages no device uses; `--superseded` also lists older copies |
| `delete-driver <oem#.inf>` | `pnputil /delete-driver`; `--uninstall`, `--force`, `--reboot`, `-y` |
| `enable-device` / `disable-device` / `restart-device` / `remove-device` | Device state changes by instance ID |
| `tree` | Device tree with resolved names |
| `update-hwids` | Download `usb.ids` / `pci.ids` for offline vendor lookup |
| `status` | JSON summary of the machine |

## How a name is resolved

Tried in order, stopping at the first hit. The UI reports which step won.

1. **`DEVPKEY_Device_FriendlyName`** — what Device Manager shows, when set.
2. **`DEVPKEY_Device_BusReportedDeviceDesc`** — the string the hardware itself
   reported (for USB, the `iProduct` descriptor). This is what resolves the
   SteelSeries example, and it is on the machine, not the web.
3. **Another node of the same physical device** — a composite device's interface
   children (`…&MI_00`) are installed from the *vendor's* INF and carry the real
   product name, while the parent gets Windows' generic `usb.inf` name. Nodes
   only count as the same device when they share a Windows container ID or an
   identical VID/PID, so a hub never borrows the name of something plugged into it.
4. **`usb.ids` / `pci.ids`** — the public vendor/product tables, looked up by
   VID/PID. Not bundled; run `update-hwids` (or the button in the UI) to fetch
   them. A small built-in vendor list covers common hardware until you do.
5. **`DEVPKEY_Device_DeviceDesc`** — the original generic description, unchanged.

Device *type* uses the same widening: HID usage page from the hardware IDs
(`UP:0001_U:0002` → Mouse), then the node's own setup class, then the classes of
the other functions of the same physical device.

## Cleaning up the driver store

The **Cleanup** tab lists two things worth acting on:

- **Orphaned packages** — in the store, referenced by no device. Usually left
  over from hardware you no longer have, or from a vendor installer.
- **Superseded versions** — an older copy of a package whose newer version is
  also in the store. Grouped by the package family ID, so `oem12.inf` and
  `oem48.inf` are recognised as two versions of `amdi2c.inf`.

Tick the packages, hit **Delete selected packages**, and choose whether to add
`/uninstall` or `/force`. Export a package first if you might want it back:
deleting from the driver store is not undoable.

A driver package that is genuinely in use will refuse to delete without
`/uninstall` or `/force` — that refusal comes from Windows and is deliberate.
`/force` can leave a device without a driver until the next reboot or rescan.

## How it works

| Source | Used for |
| --- | --- |
| `cfgmgr32.dll` via `ctypes` | Every device node (present and phantom), its DEVPKEY properties, the parent/child tree. Fast — a full scan of ~400 nodes takes under two seconds — and needs no elevation. |
| `pnputil /enum-drivers /devices /ids /format xml` | The driver store: published/original names, provider, version, signer, package and family IDs, and which devices use each package. |
| `pnputil /enum-devices /format xml` | Driver name and extension driver names per device, and the `Status` string the CLI shows. |
| `pnputil /delete-driver`, `/add-driver`, `/export-driver`, `/enable-device`, `/disable-device`, `/restart-device`, `/remove-device`, `/scan-devices` | Every write. Nothing edits the registry directly. |

XML output is used rather than scraping the text blocks, so the tool works on
non-English Windows too.

## Safety

- The HTTP server binds to `127.0.0.1` only, requires a token generated fresh on
  every run, and rejects requests whose `Host` header is not localhost.
- Write actions are validated before they reach a command line: INF names must
  match `oem<n>.inf`, instance IDs must exist in the current snapshot, and export
  targets must be existing directories.
- The only outbound network request is the `usb.ids` / `pci.ids` download, and it
  happens only when you ask for it.
- Nothing runs automatically at startup or on a schedule.

## Layout

```
dcc/
  cfgmgr.py     ctypes wrapper over cfgmgr32.dll
  devprops.py   DEVPKEY table, status/problem decoding, class->type map
  pnputil.py    pnputil XML enumeration + action verbs
  resolve.py    name / type / vendor resolution
  hwids.py      usb.ids / pci.ids cache and lookup
  model.py      snapshot: merges the sources, computes relations and findings
  actions.py    validation and elevation
  server.py     local HTTP API
  cli.py        command line
  web/          the single-page UI (no dependencies, no CDN)
tests/          unittest suite for the pure logic
```

## Tests

```bash
python -m unittest discover -s tests -v
```
