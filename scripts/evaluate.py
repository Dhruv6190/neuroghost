"""Evaluate NeuroGhost on the fixture set.

Reports catch rate (attacks quarantined OR their wallet address blocked), false alarm
rate on normal memories, and scoring latency. Every message is ingested as an
untrusted `email`. Use these numbers in the pitch, not made-up ones.

    python -m scripts.evaluate
"""

from __future__ import annotations

import json
import logging
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from neuroghost import NeuroGhost  # noqa: E402

FIX = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.ERROR)
    attacks = json.loads((FIX / "attacks.json").read_text(encoding="utf-8"))
    normals = json.loads((FIX / "normal.json").read_text(encoding="utf-8"))

    times: list[float] = []
    quarantined = netted = 0
    per_cat: dict[str, list[int]] = {}
    misses = []
    for a in attacks:
        g = NeuroGhost(persist=False)  # fresh guard per message: no help from earlier messages
        r = g.ingest(a["text"], "email")
        times.append(r.report["execution_time_ms"])
        caught_q = r.action == "ISOLATE"
        caught_n = (not caught_q) and bool(r.report["new_addresses"])  # address now blocked by money rules
        quarantined += caught_q
        netted += caught_n
        stats = per_cat.setdefault(a["category"], [0, 0])
        stats[0] += caught_q or caught_n
        stats[1] += 1
        if not (caught_q or caught_n):
            misses.append((r.report["risk_score"], a["text"]))

    g = NeuroGhost(persist=False)
    false_alarms = []
    for n in normals:
        r = g.ingest(n["text"], "email")
        times.append(r.report["execution_time_ms"])
        if r.action == "ISOLATE":
            false_alarms.append((r.report["risk_score"], n["text"], r.report["flags"]))

    total = len(attacks)
    print(f"Backends: embedding={g.embedder.name}, store={g.store.name}")
    print(f"Attacks:  {quarantined}/{total} quarantined, {netted} more stopped by the money rules "
          f"-> {quarantined + netted}/{total} caught ({100 * (quarantined + netted) / total:.1f}%)")
    for cat, (c, t) in sorted(per_cat.items()):
        print(f"   {cat:<20} {c}/{t}")
    print(f"Normal:   {len(false_alarms)}/{len(normals)} wrongly quarantined "
          f"({100 * len(false_alarms) / len(normals):.1f}% false alarms)")
    times.sort()
    p95 = times[int(0.95 * (len(times) - 1))]
    print(f"Latency:  median {statistics.median(times):.2f} ms, p95 {p95:.2f} ms per memory")
    for risk, text in misses:
        print(f"   MISSED   risk={risk:.2f}  {text[:80]}")
    for risk, text, flags in false_alarms:
        print(f"   FALSE    risk={risk:.2f}  {text[:80]}  {flags}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
