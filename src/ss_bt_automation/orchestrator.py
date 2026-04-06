"""End-to-end processing: dedupe, BeyondTrust match/rotate, email fallback, audit."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum

import structlog

from ss_bt_automation.beyondtrust import BeyondTrustClient, ManagedAccountMatch
from ss_bt_automation.circuit_breaker import CircuitBreaker, CircuitOpen
from ss_bt_automation.config import Settings
from ss_bt_automation.email_notifier import format_alert_email_body, send_incident_email
from ss_bt_automation.metrics import Metrics
from ss_bt_automation.models import NormalizedAlert, ProcessingStatus
from ss_bt_automation.store import StateStore

logger = structlog.get_logger(__name__)


class BtOutcome(str, Enum):
    ROTATED = "rotated"
    NOT_FOUND = "not_found"
    AMBIGUOUS = "ambiguous"
    ROTATION_ERROR = "rotation_error"


@dataclass
class BeyondTrustResult:
    outcome: BtOutcome
    managed_account_id: int | None = None
    match_detail: str | None = None
    error: str | None = None


def _hostname_candidates(hostname: str) -> list[str]:
    h = (hostname or "").strip()
    if not h:
        return []
    out = [h]
    upper = h.upper()
    if upper != h:
        out.append(upper)
    if "." in h:
        short = h.split(".", 1)[0]
        if short and short not in out:
            out.append(short)
    seen: set[str] = set()
    uniq: list[str] = []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


def _system_matches_host(m: ManagedAccountMatch, hostname: str) -> bool:
    if not m.system_name:
        return False
    sys_u = m.system_name.strip().upper()
    for h in _hostname_candidates(hostname):
        hu = h.strip().upper()
        if not hu:
            continue
        if sys_u == hu or sys_u.startswith(hu + ".") or hu == sys_u.split(".", 1)[0]:
            return True
    return False


def _resolve_managed_account(
    bt: BeyondTrustClient,
    alert: NormalizedAlert,
) -> tuple[ManagedAccountMatch | None, str]:
    for sys_name in _hostname_candidates(alert.hostname):
        try:
            m = bt.find_managed_account(sys_name, alert.account_name)
        except Exception as e:
            logger.warning(
                "managed_account_lookup_failed",
                correlation_id=alert.entity_id,
                system=sys_name,
                error=str(e),
            )
            m = None
        if m:
            return m, "exact_system"

    try:
        all_matches = bt.find_managed_account_by_account_name(alert.account_name)
    except Exception as e:
        logger.warning(
            "managed_account_list_failed",
            correlation_id=alert.entity_id,
            error=str(e),
        )
        return None, "error"

    if len(all_matches) == 0:
        return None, "none"

    if len(all_matches) == 1:
        return all_matches[0], "account_only_unique"

    filtered = [m for m in all_matches if _system_matches_host(m, alert.hostname)]
    if len(filtered) == 1:
        return filtered[0], "disambiguated_system"

    return None, "ambiguous"


def _beyondtrust_actions(
    settings: Settings,
    alert: NormalizedAlert,
) -> BeyondTrustResult:
    """Lookup + rotate only (no email). Used inside circuit breaker."""
    with BeyondTrustClient(settings) as bt:
        chosen, how = _resolve_managed_account(bt, alert)

        if how == "ambiguous":
            return BeyondTrustResult(
                outcome=BtOutcome.AMBIGUOUS,
                match_detail=how,
            )

        if chosen is None:
            return BeyondTrustResult(
                outcome=BtOutcome.NOT_FOUND,
                match_detail=how,
            )

        try:
            bt.change_credentials(chosen.account_id)
        except Exception as e:
            return BeyondTrustResult(
                outcome=BtOutcome.ROTATION_ERROR,
                managed_account_id=chosen.account_id,
                match_detail=how,
                error=str(e),
            )

        return BeyondTrustResult(
            outcome=BtOutcome.ROTATED,
            managed_account_id=chosen.account_id,
            match_detail=how,
        )


def process_normalized_alert(
    settings: Settings,
    store: StateStore,
    metrics: Metrics,
    circuit: CircuitBreaker,
    alert: NormalizedAlert,
) -> ProcessingStatus:
    """Process a single normalized alert (idempotent)."""
    correlation_id = alert.entity_id
    log = logger.bind(correlation_id=correlation_id)

    if store.is_processed(alert.entity_id):
        metrics.inc("alerts_duplicate_total")
        log.info("skip_duplicate")
        return ProcessingStatus.DUPLICATE

    bt_result: BeyondTrustResult | None = None
    try:
        bt_result = circuit.call(lambda: _beyondtrust_actions(settings, alert))
    except CircuitOpen:
        log.error("circuit_open_skipped")
        metrics.inc("beyondtrust_circuit_open_total")
        store.record_failed_event(
            alert.entity_id,
            json.dumps(alert.raw),
            "circuit_open",
        )
        return ProcessingStatus.ROTATION_FAILED

    assert bt_result is not None

    if bt_result.outcome == BtOutcome.AMBIGUOUS:
        metrics.inc("unmatched_account_total")
        body = format_alert_email_body(
            alert,
            reason="Ambiguous managed account match in Password Safe",
            extra={"resolution": bt_result.match_detail},
        )
        send_incident_email(
            settings,
            subject=(
                f"[IR] Ambiguous Password Safe match — {alert.hostname} / "
                f"{alert.account_name}"
            ),
            body=body,
        )
        store.mark_processed(
            alert.entity_id,
            ProcessingStatus.EMAIL_SENT_AMBIGUOUS.value,
            detail=bt_result.match_detail or "",
        )
        metrics.inc("email_sent_total")
        return ProcessingStatus.EMAIL_SENT_AMBIGUOUS

    if bt_result.outcome == BtOutcome.NOT_FOUND:
        metrics.inc("unmatched_account_total")
        body = format_alert_email_body(
            alert,
            reason="Managed account not found in Password Safe",
            extra={"resolution": bt_result.match_detail},
        )
        send_incident_email(
            settings,
            subject=(
                f"[IR] Ransomware alert — no Password Safe account — {alert.hostname}"
            ),
            body=body,
        )
        store.mark_processed(
            alert.entity_id,
            ProcessingStatus.EMAIL_SENT_UNMATCHED.value,
            detail=bt_result.match_detail or "",
        )
        metrics.inc("email_sent_total")
        return ProcessingStatus.EMAIL_SENT_UNMATCHED

    if bt_result.outcome == BtOutcome.ROTATION_ERROR:
        metrics.inc("rotation_failed_total")
        store.record_failed_event(
            alert.entity_id,
            json.dumps(alert.raw),
            bt_result.error or "rotation_error",
        )
        store.mark_processed(
            alert.entity_id,
            ProcessingStatus.ROTATION_FAILED.value,
            detail=bt_result.error or "",
        )
        body = format_alert_email_body(
            alert,
            reason="Credential rotation failed",
            extra={
                "managed_account_id": bt_result.managed_account_id,
                "error": bt_result.error,
            },
        )
        send_incident_email(
            settings,
            subject=(
                f"[IR] Password rotation failed — {alert.hostname} / "
                f"{alert.account_name}"
            ),
            body=body,
        )
        metrics.inc("email_sent_total")
        return ProcessingStatus.ROTATION_FAILED

    metrics.inc("rotation_triggered_total")
    store.mark_processed(
        alert.entity_id,
        ProcessingStatus.ROTATION_TRIGGERED.value,
        detail=(
            f"managed_account_id={bt_result.managed_account_id};"
            f"how={bt_result.match_detail}"
        ),
    )
    log.info(
        "rotation_triggered",
        managed_account_id=bt_result.managed_account_id,
        match=bt_result.match_detail,
    )
    return ProcessingStatus.ROTATION_TRIGGERED


def poll_and_process(
    settings: Settings,
    store: StateStore,
    metrics: Metrics,
    circuit: CircuitBreaker,
) -> None:
    """One polling cycle: SecuritySnares -> normalize -> process each."""
    from ss_bt_automation.securitysnares import SecuritySnaresClient

    client = SecuritySnaresClient(settings)
    metrics.inc("poll_cycles_total")
    try:
        alerts = client.fetch_ransomware_alerts()
    except Exception:
        logger.exception("securitysnares_poll_failed")
        metrics.inc("securitysnares_poll_failures_total")
        return

    metrics.inc("alerts_polled_total", len(alerts))
    for a in alerts:
        norm = client.to_normalized(a)
        if not norm:
            metrics.inc("alerts_invalid_total")
            logger.warning("skip_invalid_alert", entity_id=a.entity_id)
            if a.entity_id:
                store.mark_processed(
                    a.entity_id,
                    ProcessingStatus.SKIPPED_INVALID.value,
                    "missing fields",
                )
            continue

        status = process_normalized_alert(settings, store, metrics, circuit, norm)
        if status != ProcessingStatus.DUPLICATE:
            metrics.inc("alerts_processed_total")
