import time
import unittest

import helpers
from helpers import finding_keys, run_json

from fgaudit import synth
from fgaudit.synth import FGConfig, add_factory, change_pair, clean_config, faulty_config, policy

VERSIONS = ("7.4", "7.6", "8.0")


def small(version="7.6"):
    c = FGConfig(version)
    add_factory(c)
    ifs = c.g("system interface")
    ifs.edit("port1").set("vdom", "root").set("ip", ["192.0.2.1", "255.255.255.0"])
    ifs.edit("port2").set("vdom", "root").set("ip", ["10.1.0.1", "255.255.0.0"])
    a = c.t("firewall address")
    a.edit("net16").set("subnet", ["10.1.0.0", "255.255.0.0"])
    a.edit("net24").set("subnet", ["10.1.2.0", "255.255.255.0"])
    a.edit("other24").set("subnet", ["10.2.0.0", "255.255.255.0"])
    return c


def audit(c):
    rc, rep, err = run_json("x.conf", files={"x.conf": c.render()})
    assert rep is not None, err
    return rc, rep


class ShadowTests(unittest.TestCase):
    def test_injected_faults_found_all_versions(self):
        for v in VERSIONS:
            for vm in (False, True):
                with self.subTest(version=v, vdoms=vm):
                    c, exp, _ = faulty_config(v, vm)
                    rc, rep = audit(c)
                    self.assertEqual(rc, 1)
                    keys = finding_keys(rep)
                    for e in exp:
                        match = [k for k in keys if k[0] == e.code and all(o in k[1] for o in e.objects)]
                        self.assertTrue(match, f"{e} not found in {sorted(keys)}")
                    # nothing beyond the injected faults (and the DHCP range made overlapping by port6)
                    shadow_codes = {k for k in keys if k[0].startswith("shadow.")}
                    expected_shadow = {(e.code, tuple(e.objects)) for e in exp if e.code.startswith("shadow.")}
                    self.assertEqual(shadow_codes, expected_shadow)

    def test_clean_reference_has_no_findings(self):
        for v in VERSIONS:
            for vm in (False, True):
                with self.subTest(version=v, vdoms=vm):
                    rc, rep = audit(clean_config(v, vm))
                    self.assertEqual(rep["findings"], [], [f["title"] for f in rep["findings"]])
                    self.assertEqual(rc, 0)

    def test_partial_overlap_is_not_shadow(self):
        c = small()
        policy(c, 1, srcaddr=["net24"], dstaddr=["all"], service=["HTTPS"], action="deny")
        policy(c, 2, srcaddr=["net16"], dstaddr=["all"], service=["HTTPS"])  # bigger than 1
        policy(c, 3, srcaddr=["net24"], dstaddr=["all"], service=["web-and-ssh"])  # service bigger
        c.t("firewall service group").edit("web-and-ssh").set("member", ["HTTPS", "SSH"])
        rc, rep = audit(c)
        self.assertEqual([f for f in rep["findings"] if f["check"] == "shadow"], [])

    def test_dynamic_objects_are_not_checkable(self):
        c = small()
        a = c.t("firewall address")
        a.edit("fq").set("type", "fqdn").set("fqdn", "example.com")
        a.edit("geo").set("type", "geography").set("country", "AT")
        a.edit("dyn").set("type", "dynamic").set("sdn", "demo-connector")
        c.t("firewall vip").edit("v1").set("extip", "192.0.2.10").set("mappedip", ["10.1.2.10"]).set("extintf", "port1")
        policy(c, 1, srcaddr=["net16"], dstaddr=["fq"], service=["ALL"], action="deny")
        policy(c, 2, srcaddr=["net24"], dstaddr=["geo"], service=["HTTPS"])
        policy(c, 3, srcaddr=["net24"], dstaddr=["dyn"], service=["HTTPS"])
        policy(c, 4, srcintf=["port1"], dstintf=["port2"], srcaddr=["all"], dstaddr=["all"], service=["ALL"], action="deny")
        policy(c, 5, srcintf=["port1"], dstintf=["port2"], srcaddr=["all"], dstaddr=["v1"], service=["HTTPS"])
        policy(c, 6, srcaddr=["net24"], service=["HTTPS"], internet_service="enable", internet_service_name=["Demo-Service"], dstaddr=None)
        rc, rep = audit(c)
        codes = {(f["code"], f["params"]["later"]) for f in rep["findings"] if f["check"] == "shadow"}
        self.assertIn(("shadow.uncertain", "2"), codes)
        self.assertIn(("shadow.uncertain", "3"), codes)
        self.assertIn(("shadow.uncertain", "5"), codes)  # VIP under dstaddr all
        self.assertIn(("shadow.uncertain", "6"), codes)  # Internet Service
        self.assertFalse(any(c[0] != "shadow.uncertain" for c in codes), codes)

    def test_same_fqdn_object_is_comparable(self):
        c = small()
        c.t("firewall address").edit("fq").set("type", "fqdn").set("fqdn", "example.com")
        policy(c, 1, srcaddr=["net16"], dstaddr=["fq"], service=["ALL"], action="deny")
        policy(c, 2, srcaddr=["net24"], dstaddr=["fq"], service=["HTTPS"])
        rc, rep = audit(c)
        self.assertEqual({f["code"] for f in rep["findings"] if f["check"] == "shadow"}, {"shadow.conflict"})

    def test_order_counts_not_id(self):
        c = small()
        policy(c, 9, srcaddr=["net16"], service=["ALL"], action="deny")
        policy(c, 3, srcaddr=["net24"], service=["HTTPS"])
        rc, rep = audit(c)
        f = [f for f in rep["findings"] if f["code"] == "shadow.conflict"]
        self.assertEqual(len(f), 1)
        self.assertEqual((f[0]["params"]["later"], f[0]["params"]["earlier"]), ("3", "9"))
        self.assertTrue(f[0]["params"]["id_order_differs"])
        # reversed file order: no shadow, even though IDs are the same
        c2 = small()
        policy(c2, 3, srcaddr=["net24"], service=["HTTPS"])
        policy(c2, 9, srcaddr=["net16"], service=["ALL"], action="deny")
        rc, rep = audit(c2)
        self.assertEqual([f for f in rep["findings"] if f["check"] == "shadow"], [])

    def test_disabled_schedule_users_zone(self):
        c = small()
        c.t("system zone").edit("lan").set("interface", ["port2"])
        c.t("firewall schedule recurring").edit("office").set("day", ["monday"]).set("start", "08:00").set("end", "17:00")
        c.t("user local").edit("bob").set("type", "password")
        c.t("user group").edit("g1").set("member", ["bob"])
        policy(c, 1, srcaddr=["net16"], service=["ALL"], action="deny", status="disable")
        policy(c, 2, srcaddr=["net24"], service=["HTTPS"])  # disabled 1 must not shadow
        policy(c, 3, srcaddr=["other24"], service=["ALL"], action="deny", schedule="office")
        policy(c, 4, srcaddr=["other24"], service=["HTTPS"])  # always vs office: not covered
        policy(c, 5, srcintf=["lan"], srcaddr=["net16"], dstaddr=["all"], service=["SSH"], action="deny", groups=["g1"])
        policy(c, 6, srcaddr=["net24"], service=["SSH"])  # no users: not covered by group policy
        policy(c, 7, srcaddr=["net24"], service=["SSH"], users=["bob"])  # bob is in g1 and zone lan contains port2: 5 covers 7
        rc, rep = audit(c)
        keys = {(f["code"], f["params"]["later"], f["params"]["earlier"]) for f in rep["findings"] if f["check"] == "shadow"}
        self.assertEqual(keys, {("shadow.conflict", "7", "5")})

    def test_ports_and_negation_v6(self):
        c = small()
        svc = c.t("firewall service custom")
        svc.edit("t8080-hi").set("tcp-portrange", "8080:1024-65535")
        svc.edit("t8080").set("tcp-portrange", "8080")
        svc.edit("t8000-9000").set("tcp-portrange", "8000-9000")
        policy(c, 1, srcaddr=["net16"], service=["t8080-hi"], action="deny")
        policy(c, 2, srcaddr=["net24"], dstaddr=["other24"], service=["t8080"])  # any source port: not covered
        policy(c, 3, srcaddr=["net24"], service=["t8000-9000"], action="deny", dstaddr=["other24"], dstaddr_negate="enable")
        policy(c, 4, srcaddr=["net24"], service=["t8080"], dstaddr=["all"])  # dst all not inside "not other24"
        c.t("firewall address").edit("ext").set("subnet", ["198.51.100.0", "255.255.255.0"])
        policy(c, 5, srcaddr=["net24"], service=["t8080"], dstaddr=["ext"])  # inside "not other24" -> conflict with 3
        c.t("firewall address6").edit("p6").set("ip6", "2001:db8:1::/48")
        c.t("firewall address6").edit("h6").set("ip6", "2001:db8:1::5/128")
        policy(c, 6, srcaddr=None, dstaddr=None, srcaddr6=["p6"], dstaddr6=["all"], service=["ALL"], action="deny")
        policy(c, 7, srcaddr=None, dstaddr=None, srcaddr6=["h6"], dstaddr6=["all"], service=["HTTPS"])
        policy(c, 8, srcaddr=["net24"], dstaddr=["other24"], srcaddr6=["h6"], dstaddr6=["all"], service=["HTTPS"])  # v4 part not covered
        rc, rep = audit(c)
        keys = {(f["code"], f["params"]["later"], f["params"]["earlier"]) for f in rep["findings"] if f["check"] == "shadow"}
        self.assertEqual(keys, {("shadow.conflict", "5", "3"), ("shadow.conflict", "7", "6")})


class OverlapTests(unittest.TestCase):
    def test_no_false_alarms_for_normal_cases(self):
        for v in VERSIONS:
            rc, rep = audit(clean_config(v))
            self.assertEqual([f for f in rep["findings"] if f["check"] == "overlap"], [])

    def test_cross_vdom_is_info(self):
        c = clean_config("8.0", vdom_mode=True)
        c.g("system interface").edit("port5").set("ip", ["10.10.0.1", "255.255.255.0"])
        rc, rep = audit(c)
        f = [f for f in rep["findings"] if f["code"].startswith("overlap.")]
        self.assertEqual([x["code"] for x in f], ["overlap.interface-vdom"])
        self.assertEqual(f[0]["severity"], "info")
        p = f[0]["params"]
        self.assertEqual({p["a_vdom"], p["b_vdom"]}, {"root", "dmz-vd"})
        self.assertEqual(p["overlap"], "10.10.0.0/24")
        self.assertEqual(rc, 0)

    def test_vrf_overlap_is_info(self):
        c = clean_config("7.6")
        c.g("system interface").edit("port7").set("vdom", "root").set("ip", ["10.10.0.1", "255.255.255.0"]).set("vrf", 5)
        rc, rep = audit(c)
        self.assertEqual([(f["code"], f["severity"]) for f in rep["findings"]], [("overlap.interface-vrf", "info")])

    def test_findings_name_both_objects_and_range(self):
        c, _, _ = faulty_config("7.6")
        rc, rep = audit(c)
        for f in rep["findings"]:
            if f["check"] == "overlap":
                self.assertEqual(len(f["objects"]), 2)
                self.assertTrue(f["params"]["overlap"])
                self.assertIn(f["params"]["overlap"].split("/")[0].split("-")[0], f["detail"])


class ChangeTests(unittest.TestCase):
    def test_change_scenario_all_versions(self):
        for v in VERSIONS:
            with self.subTest(version=v):
                before, after, exp, forbidden = change_pair(v)
                rc, rep, err = run_json("before.conf", "after.conf", files={"before.conf": before, "after.conf": after})
                self.assertEqual(rc, 1)
                keys = finding_keys(rep)
                for e in exp:
                    self.assertTrue([k for k in keys if k[0] == e.code and all(o in k[1] for o in e.objects)], f"{e} missing: {sorted(keys)}")
                codes = {k[0] for k in keys}
                self.assertNotIn("change.other", codes)
                self.assertEqual(rep["stats"]["risk"], "high")
                order = [f for f in rep["findings"] if f["code"] == "change.order-conflict"]
                self.assertEqual(len(order), 1)
                ids = {o["id"] for o in order[0]["objects"]}
                self.assertEqual(ids, {"3", "4"})

    def test_noise_only_is_clean(self):
        """Same config, different UUIDs, ENC values, header build, entry order and CRLF."""
        a = clean_config("7.6", salt="one").render()
        cb = clean_config("7.6", salt="two")
        cb.build += 1
        cb.t("firewall address").entries.reverse()
        b = cb.render(crlf=True, bom=True)
        rc, rep, err = run_json("a.conf", "b.conf", files={"a.conf": a, "b.conf": b})
        self.assertEqual(rc, 0, [f["title"] for f in rep["findings"]])
        self.assertTrue(rep["findings"])  # ENC values are reported as not comparable ...
        self.assertTrue(all(f["code"] == "change.secret-not-comparable" and f["severity"] == "info" for f in rep["findings"]))
        self.assertTrue(all("not comparable" in f["title"] for f in rep["findings"]))

    def test_object_change_lists_affected_policies(self):
        before, after, _, _ = change_pair("8.0")
        rc, rep, err = run_json("b.conf", "a.conf", files={"b.conf": before, "a.conf": after})
        f = [f for f in rep["findings"] if f["code"] == "change.object" and f["objects"][0]["name"] == "web-srv"][0]
        self.assertEqual([i["id"] for i in f["params"]["impact"]], ["1"])

    def test_identical_is_zero(self):
        a = clean_config("7.4", salt="same").render()
        rc, rep, err = run_json("a.conf", "b.conf", files={"a.conf": a, "b.conf": a})
        self.assertEqual(rc, 0)
        self.assertEqual(rep["findings"], [])


class TimelineTests(unittest.TestCase):
    def test_incident_scenario(self):
        for v in VERSIONS:
            with self.subTest(version=v):
                files, truth = synth.incident_logs(v)
                rc, rep, err = run_json(*files.keys(), files=files)
                self.assertEqual(rc, 1)
                inc = [f for f in rep["findings"] if f["code"] == "timeline.incident"]
                self.assertGreaterEqual(len(inc), truth["incidents_min"])
                first = min(inc, key=lambda f: f["params"]["n"])
                t = first["params"]["trigger"]
                self.assertEqual((t["category"], t["object"], t["device"]), truth["trigger"])
                self.assertEqual(first["params"]["confidence"], "high")
                self.assertTrue(truth["chain_cats"] <= {c["category"] for c in first["params"]["chain"]})
                self.assertIn("Hypothesis", first["detail"])
                self.assertIsNotNone(first["params"]["precursor"])
                ev = rep["timeline"]["events"]
                self.assertIn(truth["repeat_count"], [e["count"] for e in ev])
                self.assertEqual(rep["timeline"]["unknown"][0]["logid"], truth["unknown_logid"])
                self.assertEqual(rep["timeline"]["unknown"][0]["count"], truth["unknown_count"])
                st = rep["timeline"]["stats"]
                self.assertEqual(st["unparseable"] + st["no_time"], truth["unparseable"])
                self.assertEqual(st["traffic"], truth["traffic"])
                self.assertEqual(st["tz_missing"], truth["tz_missing"])
                self.assertTrue(any(n["code"] == "no-tz" for n in rep["notices"]))
                # sorted by time
                ts = [e["ts"] for e in ev]
                self.assertEqual(ts, sorted(ts))

    def test_quiet_logs_exit_zero(self):
        line = 'date=2026-01-01 time=10:00:00 devname="fw" devid="FGVMDEMO" eventtime=1767261600000000000 tz="+0100" logid="0100032001" type="event" subtype="system" level="information" user="a" msg="ok"\n'
        rc, rep, err = run_json("a.log", files={"a.log": line * 3})
        self.assertEqual(rc, 0)
        self.assertEqual(rep["timeline"]["events"][0]["count"], 3)


class LargeConfigTest(unittest.TestCase):
    def test_5000_policies(self):
        text, injected = synth.large_config(5000)
        t0 = time.perf_counter()
        rc, rep, err = run_json("big.conf", files={"big.conf": text})
        dt = time.perf_counter() - t0
        print(f"\n  [large config] 5000 policies: {dt:.1f} s")
        self.assertLess(dt, 120)
        keys = {(f["params"].get("later"), f["params"].get("earlier")) for f in rep["findings"] if f["code"] == "shadow.conflict"}
        for inj in injected:
            self.assertIn(inj, keys)


if __name__ == "__main__":
    unittest.main()
