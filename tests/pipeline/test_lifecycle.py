"""Locked decision 2: re-detection after closure, one test per row of the table."""

from datetime import UTC, date, datetime, timedelta

import pytest

from vmp.pipeline.lifecycle import Outcome, redetect
from vmp.schema.enums import ClosureReason
from vmp.schema.vulnerability import Closure, HistoryEvent, Vulnerability

CLOSED = datetime(2026, 9, 1, tzinfo=UTC)


def vuln(reason: ClosureReason | None, accepted_until: date | None = None) -> Vulnerability:
    return Vulnerability(
        vulnerability_id="vln_a", finding_ids=("fnd_1",),
        status="closed" if reason else "open",  # type: ignore[arg-type]
        closure=Closure(reason=reason, closed_at=CLOSED, accepted_until=accepted_until)
        if reason else None,
        history=(HistoryEvent(at=CLOSED - timedelta(days=10), kind="created"),))


def again(v: Vulnerability, days: int) -> object:
    return redetect(v, "fnd_2", CLOSED + timedelta(days=days), new_vulnerability_id="vln_b")


def test_open_vulnerability_gets_a_sighting() -> None:
    r = again(vuln(None), 5)
    assert r.outcome is Outcome.SIGHTING  # type: ignore[attr-defined]
    assert r.prior.finding_ids == ("fnd_1", "fnd_2")  # type: ignore[attr-defined]


def test_fixed_then_seen_within_n_days_reopens() -> None:
    r = again(vuln(ClosureReason.FIXED), 30)
    assert r.outcome is Outcome.REOPENED  # type: ignore[attr-defined]
    assert (r.prior.status, r.prior.closure) == ("open", None)  # type: ignore[attr-defined]
    assert r.prior.history[-1].kind == "reopened"  # type: ignore[attr-defined]


def test_fixed_then_seen_after_n_days_is_a_linked_recurrence() -> None:
    r = again(vuln(ClosureReason.FIXED), 31)
    assert r.outcome is Outcome.RECURRENCE  # type: ignore[attr-defined]
    assert r.prior.status == "closed"  # type: ignore[attr-defined]
    assert (r.new.recurrence_of, r.new.finding_ids) == ("vln_a", ("fnd_2",))  # type: ignore[attr-defined]


def test_n_is_configurable() -> None:
    r = redetect(vuln(ClosureReason.FIXED), "fnd_2", CLOSED + timedelta(days=45),
                 new_vulnerability_id="vln_b", reopen_within=timedelta(days=90))
    assert r.outcome is Outcome.REOPENED


@pytest.mark.parametrize("days", [1, 400])
def test_false_positive_stays_suppressed(days: int) -> None:
    r = again(vuln(ClosureReason.FALSE_POSITIVE), days)
    assert r.outcome is Outcome.STAYS_SUPPRESSED  # type: ignore[attr-defined]
    assert r.prior.status == "closed"  # type: ignore[attr-defined]
    assert "fnd_2" in r.prior.finding_ids  # type: ignore[attr-defined]


def test_risk_accepted_holds_until_expiry_then_reopens() -> None:
    v = vuln(ClosureReason.RISK_ACCEPTED, accepted_until=date(2026, 12, 31))
    held = redetect(v, "fnd_2", datetime(2026, 12, 31, 23, tzinfo=UTC), new_vulnerability_id="x")
    assert held.outcome is Outcome.STAYS_ACCEPTED
    expired = redetect(v, "fnd_3", datetime(2027, 1, 1, tzinfo=UTC), new_vulnerability_id="x")
    assert expired.outcome is Outcome.REOPENED
    assert expired.prior.history[-1].detail == "risk acceptance expired 2026-12-31"


def test_same_finding_twice_is_a_no_op() -> None:
    v = vuln(None)
    assert redetect(v, "fnd_1", CLOSED, new_vulnerability_id="x").prior == v
