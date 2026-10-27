"""Re-detection after closure, locked decision 2. Pure rules: record in, record(s) out.

A re-detection always arrives as a new Finding. What happens to the Vulnerability depends on
why it was closed:

| closed as      | re-detected                  | outcome                                        |
|----------------|------------------------------|------------------------------------------------|
| (still open)   | any time                     | sighting: the finding is added                 |
| fixed          | within N days of closure     | reopen: the fix failed                         |
| fixed          | after N days                 | new record, linked to the old as a recurrence  |
| false positive | any time                     | stays suppressed; finding kept as evidence     |
| risk accepted  | on or before accepted_until  | stays accepted; finding added                  |
| risk accepted  | after accepted_until         | reopen: the acceptance has expired             |

Records are frozen, so every outcome returns new versions with a history event, never an edit.
Nothing calls this on a stateless folder run (nothing is closed yet); it's ready for storage.
"""

from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum

from pydantic import AwareDatetime

from vmp.schema.enums import ClosureReason, VulnerabilityStatus
from vmp.schema.vulnerability import HistoryEvent, Vulnerability

DEFAULT_REOPEN_WITHIN = timedelta(days=30)  # "N", configurable; the skill allows 30-90


class Outcome(StrEnum):
    SIGHTING = "sighting"
    REOPENED = "reopened"
    RECURRENCE = "recurrence"
    STAYS_SUPPRESSED = "stays_suppressed"
    STAYS_ACCEPTED = "stays_accepted"


@dataclass(frozen=True)
class Redetection:
    outcome: Outcome
    prior: Vulnerability  # the existing record's new version (or unchanged, for a recurrence)
    new: Vulnerability | None = None  # the recurrence record, when one is created


def redetect(prior: Vulnerability, finding_id: str, at: AwareDatetime, *,
             new_vulnerability_id: str,
             reopen_within: timedelta = DEFAULT_REOPEN_WITHIN) -> Redetection:
    if prior.status is VulnerabilityStatus.OPEN:
        return Redetection(Outcome.SIGHTING, _add(prior, finding_id))

    closure = prior.closure
    assert closure is not None  # the model guarantees closure iff closed
    if closure.reason is ClosureReason.FALSE_POSITIVE:
        return Redetection(Outcome.STAYS_SUPPRESSED, _add(prior, finding_id))

    if closure.reason is ClosureReason.RISK_ACCEPTED:
        assert closure.accepted_until is not None
        if at.date() <= closure.accepted_until:
            return Redetection(Outcome.STAYS_ACCEPTED, _add(prior, finding_id))
        return Redetection(Outcome.REOPENED, _reopen(
            prior, finding_id, at, f"risk acceptance expired {closure.accepted_until}"))

    # Fixed.
    if at - closure.closed_at <= reopen_within:
        return Redetection(Outcome.REOPENED, _reopen(
            prior, finding_id, at, f"re-detected {(at - closure.closed_at).days} days after fix"))
    new = Vulnerability(
        vulnerability_id=new_vulnerability_id, finding_ids=(finding_id,),
        status=VulnerabilityStatus.OPEN, recurrence_of=prior.vulnerability_id,
        history=(HistoryEvent(at=at, kind="created"),
                 HistoryEvent(at=at, kind="recurrence_linked",
                              detail=f"recurrence of {prior.vulnerability_id}")))
    return Redetection(Outcome.RECURRENCE, prior, new)


def _add(v: Vulnerability, finding_id: str) -> Vulnerability:
    if finding_id in v.finding_ids:
        return v  # re-ingesting the same file is a no-op
    return v.model_copy(update={"finding_ids": (*v.finding_ids, finding_id)})


def _reopen(v: Vulnerability, finding_id: str, at: AwareDatetime, why: str) -> Vulnerability:
    return Vulnerability.model_validate({
        **_add(v, finding_id).model_dump(),
        "status": VulnerabilityStatus.OPEN, "closure": None,
        "history": (*v.history, HistoryEvent(at=at, kind="reopened", detail=why)),
    })
