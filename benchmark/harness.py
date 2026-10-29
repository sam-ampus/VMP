"""Run the constructed FP benchmark and report how FP triage did.

    uv run python -m benchmark                 # all cases in benchmark/cases/
    uv run python -m benchmark --cases DIR     # another folder (e.g. local-only real cases)

Each case has a ground truth ("real" or "false_positive") and, optionally, the band the
rules are expected to give. Metrics:

- precision / recall of the "not real" call (likely_false_positive, confirmed_not_applicable)
- review rate: how much lands on an analyst as needs_review
- HARD RULE: a real issue must never be called not real. Any such case fails the run.

The second failure is a case whose band differs from its "expect": the benchmark is also the
regression suite for the rules. Cases where the rules knowingly fall short (a backported
banner the scanner can't see past) expect needs_review and count against recall, on purpose:
the number should show the limitation, not hide it.

Measured on constructed cases until analyst dispositions exist (skill rule).
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from benchmark.build import findings
from vmp.pipeline.assess_fp import NOT_REAL, REAL, assess_fp, combine
from vmp.pipeline.correlate import correlate
from vmp.schema.enums import FPBand

CASES = Path(__file__).parent / "cases"


@dataclass(frozen=True)
class Outcome:
    case_id: str
    category: str
    truth: str  # real | false_positive
    band: FPBand
    expected: FPBand | None
    groups: int  # vulnerabilities the case's findings correlated into

    @property
    def called_not_real(self) -> bool:
        return self.band in NOT_REAL

    @property
    def violation(self) -> bool:
        return self.truth == "real" and self.called_not_real


@dataclass(frozen=True)
class Report:
    outcomes: tuple[Outcome, ...]

    def metrics(self, category: str | None = None) -> dict[str, Any]:
        xs = [o for o in self.outcomes if category in (None, o.category)]
        called = [o for o in xs if o.called_not_real]
        actual = [o for o in xs if o.truth == "false_positive"]
        hits = [o for o in called if o.truth == "false_positive"]
        return {
            "cases": len(xs),
            "false_positives": len(actual),
            "called_not_real": len(called),
            "precision": _ratio(len(hits), len(called)),
            "recall": _ratio(len(hits), len(actual)),
            "review_rate": _ratio(sum(o.band is FPBand.NEEDS_REVIEW for o in xs), len(xs)),
            "fp_called_real": sum(o.truth == "false_positive" and o.band in REAL for o in xs),
            "violations": [o.case_id for o in xs if o.violation],
        }

    @property
    def mismatches(self) -> list[Outcome]:
        return [o for o in self.outcomes
                if (o.expected and o.band is not o.expected) or o.groups != 1]

    @property
    def ok(self) -> bool:
        return not self.metrics()["violations"] and not self.mismatches


def run(cases_dir: Path = CASES) -> Report:
    outcomes = []
    for path in sorted(cases_dir.glob("*.json")):
        suite = json.loads(path.read_text(encoding="utf-8"))
        for case in suite["cases"]:
            outcomes.append(_run_case(suite["category"], case))
    return Report(tuple(outcomes))


def _run_case(category: str, case: dict[str, Any]) -> Outcome:
    fs = findings(case)
    assessments = [assess_fp(f) for f in fs]
    groups = correlate(fs, {})
    # A case is one issue: its findings must correlate into one vulnerability. The
    # cross-scanner category exists to check exactly that.
    vid = groups[0].vulnerability.vulnerability_id if groups else "none"
    band = combine(vid, fs, assessments).band
    expected = FPBand(case["expect"]) if case.get("expect") else None
    return Outcome(case["id"], category, case["truth"], band, expected, len(groups))


def render(report: Report) -> str:
    categories = sorted({o.category for o in report.outcomes})
    lines = [f"{'category':<31} {'cases':>5} {'FPs':>4} {'called':>6} {'prec':>5} {'recall':>6} "
             f"{'review':>6}"]
    for c in [*categories, None]:
        m = report.metrics(c)
        lines.append(f"{c or 'ALL':<31} {m['cases']:>5} {m['false_positives']:>4} "
                     f"{m['called_not_real']:>6} {_pct(m['precision']):>5} "
                     f"{_pct(m['recall']):>6} {_pct(m['review_rate']):>6}")
    m = report.metrics()
    lines += ["", "bands: " + ", ".join(f"{b} {n}" for b, n in sorted(
        Counter(str(o.band) for o in report.outcomes).items())),
        f"false positives called real: {m['fp_called_real']}"]
    by_cat: dict[str, list[str]] = defaultdict(list)
    for o in report.mismatches:
        by_cat[o.category].append(
            f"  MISMATCH {o.case_id}: got {o.band}, expected {o.expected}, groups {o.groups}")
    for c in sorted(by_cat):
        lines += by_cat[c]
    if m["violations"]:
        lines.append("HARD RULE BROKEN (real issue called not real): "
                     + ", ".join(m["violations"]))
    lines.append("PASS" if report.ok else "FAIL")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m benchmark")
    parser.add_argument("--cases", type=Path, default=CASES)
    args = parser.parse_args(argv)
    report = run(args.cases)
    sys.stdout.write(render(report))
    return 0 if report.ok else 1


def _ratio(n: int, d: int) -> float | None:
    return round(n / d, 3) if d else None


def _pct(x: float | None) -> str:
    return "-" if x is None else f"{x:.0%}"
