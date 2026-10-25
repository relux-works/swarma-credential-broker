#!/usr/bin/env python3
"""Check published arithmetic and reserve feasibility, never native timing."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOC = ROOT / "docs/time-handoff.md"


def tables():
    text = DOC.read_text()
    constants, vectors = {}, {}
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) == 2 and cells[0].endswith("_ns"):
            constants[cells[0]] = int(cells[1])
        if len(cells) == 7 and cells[5] in ("true", "false"):
            vectors[cells[0]] = dict(zip(
                ("m_ns", "T_ns", "reserve_ns", "O_ns"), map(int, cells[1:5])))
            vectors[cells[0]]["history_current"] = cells[5] == "true"
            vectors[cells[0]]["expected"] = set() if cells[6] == "none" else set(cells[6].split(","))
    return text, constants, vectors


def failed_predicates(c, v):
    """Independent arithmetic requirements; these are not API refusal codes."""
    s, p, m = c["s_ns"], c["p_ns"], v["m_ns"]
    f, eps, allowance = c["f_ns"], c["epsilon_ns"], v["T_ns"]
    delta = c["source_uncertainty_ns"] + v["reserve_ns"]
    lower, upper = v["O_ns"] - delta, v["O_ns"] + delta
    predicates = {
        "capture": 0 <= s <= p <= m and eps >= 0 and f > 0 and allowance > 0,
        "coverage": m - s + f + eps <= allowance,
        "deadline": m + f + eps < c["D_ns"],
        "reserve": allowance <= v["reserve_ns"],
        "cap": delta <= c["cap_ns"],
        "interval": lower > max(c["prior_W_ns"], c["J_ns"]),
        "authority": upper < c["A_ns"],
        "continuity": v["history_current"],
    }
    return {name for name, passes in predicates.items() if not passes}


class HandoffVectorConsistency(unittest.TestCase):
    # Claims: the documented full positives fit the pre-settled reserve/cap,
    # and each named negative violates exactly its independently stated numeric
    # predicates. This proves no scheduling, burn/CAS, provenance or durability.
    def test_full_positives_fit_uncertainty_cap(self):
        _, c, vectors = tables()
        positives = {name for name, v in vectors.items() if not v["expected"]}
        self.assertEqual(positives, {"timely", "deadline-neighbour",
                                     "unused-window-reprepare", "independently-authorized-window"})
        self.assertEqual(c["cap_ns"], 1500000000)
        for name in positives:
            with self.subTest(vector=name):
                v = vectors[name]
                self.assertGreaterEqual(v["reserve_ns"], v["T_ns"])
                self.assertLessEqual(c["source_uncertainty_ns"] + v["reserve_ns"], c["cap_ns"])
                self.assertEqual(failed_predicates(c, v), set())

    def test_negative_vectors_fail_named_predicates(self):
        _, c, vectors = tables()
        expected = {
            "stale-admission": {"coverage", "deadline"},
            "deadline-equality": {"deadline"},
            "old-allowance-with-fixed-reserve": {"reserve"},
            "old-allowance-with-expanded-reserve": {"cap"},
            "intact-history-lower-interval": {"interval"},
            "missing-history": {"continuity"},
            "restored-history": {"continuity"},
            "authority-equality": {"authority"},
        }
        self.assertEqual({n for n, v in vectors.items() if v["expected"]}, set(expected))
        for name, failures in expected.items():
            with self.subTest(vector=name):
                self.assertEqual(vectors[name]["expected"], failures)
                self.assertEqual(failed_predicates(c, vectors[name]), failures)

    # Claim: the narrative positive/equality examples use the same feasible
    # allowance as the executable table; a repaired table cannot hide stale prose.
    def test_published_positive_allowance_matches_arithmetic(self):
        text, c, vectors = tables()
        timely = next(line for line in text.splitlines() if line.startswith("| `HandoffTimelyRun`"))
        equality = next(line for line in text.splitlines() if line.startswith("| `HandoffDeadlineEquality`"))
        for line, name in [(timely.split("|")[3], "timely"),
                           (equality.split("|")[2], "deadline-equality")]:
            with self.subTest(vector=name):
                actual = {key + "_ns": int(value) * 1000000 for key, value in
                          re.findall(r"\b(s|p|m|f|epsilon|T|D)=(\d+)", line)}
                self.assertEqual(set(actual), {"s_ns", "p_ns", "m_ns", "f_ns", "epsilon_ns", "T_ns", "D_ns"})
                for key, value in actual.items():
                    self.assertEqual(value, vectors[name].get(key, c.get(key)))
        neighbour = vectors["deadline-neighbour"]
        self.assertEqual(neighbour["m_ns"] + c["f_ns"] + c["epsilon_ns"], c["D_ns"] - 1)
        self.assertIn(f"m={neighbour['m_ns']} ns", equality)
        self.assertIn("source uncertainty 500 ms", text)
        self.assertIn("reserve 500 ms and total delta 1000 ms", text)
        self.assertIn("1500 ms effective cap", text)


if __name__ == "__main__":
    unittest.main()
