"""Measure fgaudit on large synthetic configs (5,000+ policies).

    python scripts/measure_large.py [N]

Prints wall-clock times for a realistic spread over 24 interfaces and for a
worst case where every policy uses the same interface pair.
"""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from fgaudit import synth  # noqa: E402
from fgaudit.cli import main  # noqa: E402


def worst_case(n):
    import random

    rnd = random.Random(3)
    c = synth.FGConfig("8.0")
    synth.add_factory(c)
    c.g("system interface").edit("port1").set("vdom", "root").set("ip", ["192.0.2.1", "255.255.255.0"])
    c.g("system interface").edit("port2").set("vdom", "root").set("ip", ["10.0.0.1", "255.0.0.0"])
    a = c.t("firewall address")
    names = []
    for i in range(2000):
        nm = f"h{i}"
        a.edit(nm).set("subnet", [f"10.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}", "255.255.255.255"])
        names.append(nm)
    svc = c.t("firewall service custom")
    snames = []
    for i in range(300):
        svc.edit(f"t{i}").set("tcp-portrange", str(10000 + i))
        snames.append(f"t{i}")
    for pid in range(1, n + 1):
        synth.policy(c, pid, srcaddr=rnd.sample(names, 2), dstaddr=rnd.sample(names, 2), service=rnd.sample(snames, 2),
                     action=rnd.choice(["accept", "deny"]))
    return c.render()


def timed(text):
    d = tempfile.mkdtemp()
    p = os.path.join(d, "big.conf")
    with open(p, "w") as fh:
        fh.write(text)
    devnull = open(os.devnull, "w")
    old = sys.stdout
    sys.stdout = devnull
    t = time.perf_counter()
    try:
        rc = main([p, "--json"])
    finally:
        sys.stdout = old
    return time.perf_counter() - t, rc, os.path.getsize(p)


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    text, _ = synth.large_config(n)
    dt, rc, size = timed(text)
    print(f"realistic: {n} policies, 24 interfaces, {size / 1e6:.1f} MB: {dt:.1f} s (exit {rc})")
    dt, rc, size = timed(worst_case(n))
    print(f"worst case: {n} policies, one interface pair, {size / 1e6:.1f} MB: {dt:.1f} s (exit {rc})")
