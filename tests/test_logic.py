"""Tests for the pure logic: parsing, resolution and validation.

None of these touch the live machine, so they run anywhere Python does
(the ctypes layer in ``dcc.cfgmgr`` is Windows-only and is not imported here).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dcc import devprops as dp  # noqa: E402
from dcc import resolve  # noqa: E402
from dcc.resolve import Resolver, hid_usage_type, is_generic_desc, parse_ids  # noqa: E402


def device(instance_id, **kw):
    base = {
        "instance_id": instance_id,
        "description": "",
        "friendly_name": "",
        "bus_reported": "",
        "class_name": "",
        "manufacturer": "",
        "hardware_ids": [],
        "compatible_ids": [],
        "children": [],
        "parent": "",
        "container_id": "",
    }
    base.update(kw)
    base["ids"] = parse_ids(instance_id, base["hardware_ids"])
    return base


COMPOSITE = "USB\\VID_1038&PID_1838\\6&2ae87d4e&0&1"
IFACE = "USB\\VID_1038&PID_1838&MI_00\\7&29656be0&0&0000"
HIDMOUSE = "HID\\VID_1038&PID_1838&MI_00&Col01\\8&324e76b&0&0000"


def steelseries_snapshot(bus_reported=""):
    """The example from the brief: a composite mouse and its child nodes."""
    container = "{aa11bb22-0000-0000-0000-000000000001}"
    devs = [
        device(COMPOSITE,
               description="USB Composite Device",
               manufacturer="(Standard USB Host Controller)",
               class_name="USB",
               bus_reported=bus_reported,
               container_id=container,
               children=[IFACE]),
        device(IFACE,
               description="SteelSeries Aerox 3 Wireless",
               manufacturer="SteelSeries ApS",
               class_name="HIDClass",
               container_id=container,
               parent=COMPOSITE,
               children=[HIDMOUSE]),
        device(HIDMOUSE,
               description="HID-compliant mouse",
               manufacturer="(Standard system devices)",
               class_name="Mouse",
               container_id=container,
               parent=IFACE,
               hardware_ids=["HID\\VID_1038&PID_1838&MI_00&Col01",
                             "HID\\VID_1038&UP:0001_U:0002",
                             "HID_DEVICE_SYSTEM_MOUSE"]),
    ]
    return {d["instance_id"]: d for d in devs}


class TestIdParsing(unittest.TestCase):
    def test_usb(self):
        ids = parse_ids(COMPOSITE)
        self.assertEqual(ids["bus"], "USB")
        self.assertEqual((ids["vid"], ids["pid"]), ("1038", "1838"))
        self.assertEqual(ids["id_kind"], "usb")

    def test_pci_with_subsystem(self):
        ids = parse_ids("PCI\\VEN_1002&DEV_1114&SUBSYS_380317AA&REV_C3\\4&230b8299&0&0041")
        self.assertEqual((ids["vid"], ids["pid"]), ("1002", "1114"))
        self.assertEqual(ids["subsys_vendor"], "17AA")
        self.assertEqual(ids["subsys_device"], "3803")
        self.assertEqual(ids["id_kind"], "pci")

    def test_no_ids(self):
        ids = parse_ids("ROOT\\SYSTEM\\0001")
        self.assertIsNone(ids["vid"])
        self.assertIsNone(ids["id_kind"])

    def test_hardware_ids_are_searched_too(self):
        ids = parse_ids("SWD\\SOMETHING\\1", ["USB\\VID_046D&PID_C534&MI_01"])
        self.assertEqual((ids["vid"], ids["pid"]), ("046D", "C534"))


class TestGenericDetection(unittest.TestCase):
    def test_generic(self):
        for text in ("USB Composite Device", "usb input device", "Generic PnP Monitor",
                     "HID-compliant mouse", "Unknown device", ""):
            self.assertTrue(is_generic_desc(text), text)

    def test_specific(self):
        for text in ("SteelSeries Aerox 3 Wireless", "AMD Radeon(TM) 840M Graphics",
                     "WH-1000XM5"):
            self.assertFalse(is_generic_desc(text), text)

    def test_generic_manufacturers(self):
        self.assertTrue(resolve.is_generic_mfg("(Standard USB Host Controller)"))
        self.assertTrue(resolve.is_generic_mfg("Microsoft"))
        self.assertFalse(resolve.is_generic_mfg("SteelSeries ApS"))


class TestHidUsage(unittest.TestCase):
    def test_usage_page(self):
        self.assertEqual(hid_usage_type(["HID\\VID_1038&UP:0001_U:0002"]), "Mouse")
        self.assertEqual(hid_usage_type(["HID\\VID_1038&UP:0001_U:0006"]), "Keyboard")
        self.assertEqual(hid_usage_type(["HID\\VID_X&UP:000D_U:0004"]), "Touch screen")

    def test_compatible_id_fallback(self):
        self.assertEqual(hid_usage_type([], ["HID_DEVICE_SYSTEM_KEYBOARD"]), "Keyboard")

    def test_nothing(self):
        self.assertIsNone(hid_usage_type(["USB\\VID_1038&PID_1838"]))


class TestResolver(unittest.TestCase):
    def test_bus_reported_name_wins(self):
        r = Resolver(steelseries_snapshot(bus_reported="SteelSeries Aerox 3 Wireless"))
        got = r.resolve_name(COMPOSITE)
        self.assertEqual(got["resolved_name"], "SteelSeries Aerox 3 Wireless")
        self.assertEqual(got["resolved_from"], "BusReportedDeviceDesc")
        self.assertEqual(got["resolved_confidence"], "high")

    def test_falls_back_to_child_name(self):
        """With no bus string, the vendor-named interface child must be used."""
        r = Resolver(steelseries_snapshot())
        got = r.resolve_name(COMPOSITE)
        self.assertEqual(got["resolved_name"], "SteelSeries Aerox 3 Wireless")
        self.assertIn(IFACE, got["resolved_from"])

    def test_type_comes_from_hid_usage_of_a_descendant(self):
        r = Resolver(steelseries_snapshot())
        got = r.resolve_type(COMPOSITE)
        self.assertEqual(got["device_type"], "Mouse")
        self.assertIn("HID usage page", got["type_from"])

    def test_vendor_is_taken_from_the_same_device(self):
        r = Resolver(steelseries_snapshot())
        self.assertEqual(r.resolve_vendor(COMPOSITE)["vendor"], "SteelSeries ApS")

    def test_unrelated_child_never_lends_its_name(self):
        """A root/hub node must not borrow the name of something plugged into it."""
        devs = steelseries_snapshot()
        root = device("HTREE\\ROOT\\0", description="",
                      container_id="{00000000-0000-0000-ffff-ffffffffffff}",
                      children=[COMPOSITE])
        devs[root["instance_id"]] = root
        devs[COMPOSITE]["parent"] = root["instance_id"]
        r = Resolver(devs)
        got = r.resolve_name("HTREE\\ROOT\\0")
        self.assertNotIn("SteelSeries", got["resolved_name"])
        self.assertEqual(got["resolved_from"], "DeviceDesc")

    def test_local_machine_container_is_not_a_device(self):
        devs = steelseries_snapshot()
        lmc = "{00000000-0000-0000-ffff-ffffffffffff}"
        for d in devs.values():
            d["container_id"] = lmc
            d["ids"] = parse_ids("ROOT\\X\\1")  # strip VID/PID so only the container is left
        r = Resolver(devs)
        self.assertFalse(r.same_physical_device(COMPOSITE, IFACE))

    def test_children_recovered_from_parent_links(self):
        devs = steelseries_snapshot()
        devs[COMPOSITE]["children"] = []  # DEVPKEY_Device_Children missing
        r = Resolver(devs)
        self.assertIn(IFACE, r.children_of(COMPOSITE))


class TestStatusDecoding(unittest.TestCase):
    def test_started(self):
        got = dp.decode_status(dp.DN_STARTED | dp.DN_DRIVER_LOADED, 0, True)
        self.assertEqual(got["status"], "Started")

    def test_stopped(self):
        self.assertEqual(dp.decode_status(0, 0, True)["status"], "Stopped")

    def test_absent_device_is_disconnected(self):
        self.assertEqual(dp.decode_status(None, None, False)["status"], "Disconnected")

    def test_disabled_problem_code(self):
        got = dp.decode_status(dp.DN_HAS_PROBLEM, 22, True)
        self.assertEqual(got["status"], "Disabled")

    def test_problem_text(self):
        got = dp.decode_status(dp.DN_HAS_PROBLEM, 43, True)
        self.assertEqual(got["status"], "Problem")
        self.assertIn("reported problems", got["problem_text"])


class TestDriverVersionSplit(unittest.TestCase):
    def setUp(self):
        from dcc.model import _split_driver_version
        self.split = _split_driver_version

    def test_date_and_version(self):
        iso, version, tup = self.split("05/19/2026 15.11.30.14")
        self.assertEqual(iso, "2026-05-19")
        self.assertEqual(version, "15.11.30.14")
        self.assertEqual(tup, (15, 11, 30, 14))

    def test_ordering_is_numeric_not_lexical(self):
        _, _, older = self.split("08/14/2025 15.11.30.9")
        _, _, newer = self.split("05/19/2026 15.11.30.14")
        self.assertGreater(newer, older)

    def test_empty(self):
        self.assertEqual(self.split(""), (None, None, ()))


class TestValidation(unittest.TestCase):
    def setUp(self):
        from dcc import actions
        self.actions = actions

    def test_oem_inf_accepted(self):
        self.assertEqual(self.actions.validate_oem_inf("OEM42.INF"), "oem42.inf")

    def test_inbox_inf_rejected(self):
        with self.assertRaises(self.actions.ActionError):
            self.actions.validate_oem_inf("usb.inf")

    def test_command_injection_rejected(self):
        for bad in ("oem1.inf & calc.exe", "oem1.inf | del *", "../oem1.inf", "oem1.inf\nrm"):
            with self.assertRaises(self.actions.ActionError):
                self.actions.validate_oem_inf(bad)

    def test_instance_id_must_be_known(self):
        with self.assertRaises(self.actions.ActionError):
            self.actions.validate_instance_id(COMPOSITE, known={"USB\\OTHER\\1"})
        self.assertEqual(
            self.actions.validate_instance_id(COMPOSITE, known={COMPOSITE}), COMPOSITE
        )

    def test_unsupported_device_verb(self):
        with self.assertRaises(self.actions.ActionError):
            self.actions.device_action("nuke-device", COMPOSITE, known={COMPOSITE})


class TestHwids(unittest.TestCase):
    def setUp(self):
        from dcc import hwids
        self.hwids = hwids

    def test_parse(self):
        table = self.hwids._parse_ids(
            "# comment\n"
            "1038  SteelSeries ApS\n"
            "\t1838  Aerox 3 Wireless\n"
            "\t\t0001  ignored interface line\n"
            "046d  Logitech, Inc.\n"
        )
        self.assertEqual(table["1038"]["name"], "SteelSeries ApS")
        self.assertEqual(table["1038"]["products"]["1838"], "Aerox 3 Wireless")
        self.assertIn("046D", table)

    def test_seed_lookup_without_download(self):
        vendor, _product = self.hwids.lookup_usb("1038", "1838")
        self.assertIsNotNone(vendor)
        self.assertIn("SteelSeries", vendor)


if __name__ == "__main__":
    unittest.main()
