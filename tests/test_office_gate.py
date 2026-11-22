"""The office-compat gate: a file whose own drawing wobbles may move by that wobble, and no more."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "office"))
import compat  # noqa: E402


def gate(base, now):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "baseline.json"
        p.write_text(json.dumps(base))
        return compat.gate(now, p)


def row(look, noise=None, text=1.0):
    r = {"file": "a.xlsx", "engine": "zenos", "saved": True, "look": look, "text": text}
    if noise is not None:
        r["look_noise"] = noise
    return r


class Gate(unittest.TestCase):
    def test_a_steady_file_may_move_by_the_noise_of_drawing_only(self):
        self.assertEqual(gate([row(0.991)], [row(0.975)]), [])
        self.assertEqual(len(gate([row(0.991)], [row(0.962)])), 1)

    def test_a_wobbling_file_may_move_by_its_measured_wobble(self):
        # 7cfa414b89d7.xlsx: the original drawn twice was 0.94 alike, and the saved file came out 0.962 against 0.991
        self.assertEqual(gate([row(0.991)], [row(0.962, noise=0.06)]), [])
        self.assertEqual(gate([row(0.991, noise=0.06)], [row(0.962)]), [])

    def test_more_than_the_wobble_is_still_refused(self):
        self.assertEqual(len(gate([row(0.991)], [row(0.80, noise=0.06)])), 1)

    def test_the_wobble_does_not_loosen_the_text(self):
        self.assertEqual(len(gate([row(0.991, text=1.0)], [row(0.991, noise=0.5, text=0.9)])), 1)


if __name__ == "__main__":
    unittest.main()
