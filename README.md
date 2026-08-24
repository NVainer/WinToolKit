# WinToolKit

Windows administration tools that answer questions the built-in utilities
answer badly. Each lives in its own folder and runs independently.

## [Device Control Console](Device_Control_Console/)

A console for the Windows driver store and device tree — the things `pnputil`
can only show you as flat text.

`pnputil /enum-devices` reports a mouse like this:

```
Instance ID:                USB\VID_1038&PID_1838\6&2ae87d4e&0&1
Device Description:         USB Composite Device
Manufacturer Name:          (Standard USB Host Controller)
```

Accurate and useless. This resolves it to **SteelSeries Aerox 3 Wireless
(Mouse)** using data already on the machine — no web lookup — and adds search,
sorting, grouping, a device-relations graph, and driver-store cleanup for
orphaned and superseded packages.

Ships three interchangeable builds sharing one web UI. Pick by what the machine
allows:

| Build | Needs | Use it when |
| --- | --- | --- |
| PowerShell | nothing (in-box) | Smart App Control / WDAC / AppLocker is enforcing |
| Native `.exe` | nothing (in-box .NET) | unsigned binaries are permitted; fastest |
| Python | Python 3.10+ | working on the code |

## [App Control Console](App_Control_Console/)

A viewer for Windows Defender Application Control policies and their audit
events, with sample base and supplemental policies to work against.

---

Both tools are Windows-only and read-only by default; anything that changes the
machine is an explicit action that shows the exact command it ran.
