"""SMTP email notifications for unmatched/ambiguous incidents."""

from __future__ import annotations

import smtplib
from email.message import EmailMessage
from typing import Any

import structlog

from ss_bt_automation.config import Settings
from ss_bt_automation.models import NormalizedAlert

logger = structlog.get_logger(__name__)


def _recipients(settings: Settings) -> list[str]:
    if not settings.admin_email_to.strip():
        return []
    return [x.strip() for x in settings.admin_email_to.split(",") if x.strip()]


def send_incident_email(
    settings: Settings,
    *,
    subject: str,
    body: str,
) -> bool:
    recipients = _recipients(settings)
    if not recipients:
        logger.error("admin_email_to_not_configured")
        return False
    if not settings.smtp_host:
        logger.error("smtp_host_not_configured")
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from or settings.smtp_user or "noreply@localhost"
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)

    try:
        if settings.smtp_use_tls:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30) as smtp:
                smtp.starttls()
                if settings.smtp_user:
                    smtp.login(settings.smtp_user, settings.smtp_password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30) as smtp:
                if settings.smtp_user:
                    smtp.login(settings.smtp_user, settings.smtp_password)
                smtp.send_message(msg)
    except Exception as e:
        logger.exception("smtp_send_failed", error=str(e))
        return False

    logger.info("email_sent", recipients=recipients)
    return True


def format_alert_email_body(
    alert: NormalizedAlert,
    *,
    reason: str,
    extra: dict[str, Any] | None = None,
) -> str:
    lines = [
        "SecuritySnares + BeyondTrust automation",
        "",
        f"Reason: {reason}",
        f"Alert entity_id: {alert.entity_id}",
        f"Hostname: {alert.hostname}",
        f"Executing user: {alert.executing_username_raw}",
        f"Parsed account: {alert.account_name}",
        f"Domain hint: {alert.domain_hint}",
        f"Process: {alert.process_name}",
        f"SHA256: {alert.process_sha256}",
        f"AI severity: {alert.ai_severity}",
        f"AI summary: {alert.ai_summary}",
        "",
    ]
    if extra:
        lines.append("Additional:")
        for k, v in extra.items():
            lines.append(f"  {k}: {v}")
    return "\n".join(lines)
