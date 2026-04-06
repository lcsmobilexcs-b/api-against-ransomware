"""SecuritySnares API client: list alerts and ransomware filtering."""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from ss_bt_automation.config import Settings
from ss_bt_automation.http_utils import with_http_retries
from ss_bt_automation.models import (
    NormalizedAlert,
    SecuritySnaresAlert,
    normalize_hostname,
    parse_ai_analysis_field,
    parse_executing_username,
)

logger = structlog.get_logger(__name__)


def _is_ransomware_alert(
    ai_analysis: str | None,
    *,
    min_severity: int,
    keyword: str,
) -> bool:
    parsed = parse_ai_analysis_field(ai_analysis)
    if parsed.severity is not None and parsed.severity >= min_severity:
        return True
    summary = (parsed.summary or "") + (ai_analysis or "")
    if keyword and keyword.lower() in summary.lower():
        return True
    return False


class SecuritySnaresClient:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._base = settings.securitysnares_base_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {settings.securitysnares_api_key}",
            "Accept": "application/json",
        }

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self._base,
            headers=self._headers,
            timeout=self._settings.http_timeout_seconds,
        )

    def _fetch_alerts_raw(self) -> list[dict[str, Any]]:
        """Fetch alerts from org or MSSP window endpoint."""

        def _do() -> list[dict[str, Any]]:
            with self._client() as client:
                if self._settings.securitysnares_use_mssp:
                    url = "/mssp/alerts"
                    params = {"minutes": self._settings.securitysnares_mssp_minutes}
                else:
                    url = "/alerts"
                    params = {"dismissed": "false"}

                resp = client.get(url, params=params)
                if resp.status_code == 400 and not self._settings.securitysnares_use_mssp:
                    resp = client.get("/alerts")
                resp.raise_for_status()
                body = resp.json()
                if not body.get("success", True):
                    raise RuntimeError(body.get("message", "SecuritySnares error"))
                data = body.get("data")
                if not isinstance(data, list):
                    return []
                return [x for x in data if isinstance(x, dict)]

        return with_http_retries(_do, max_attempts=self._settings.max_retries)()

    def fetch_ransomware_alerts(self) -> list[SecuritySnaresAlert]:
        """Return alerts that pass ransomware heuristics."""
        raw_list = self._fetch_alerts_raw()
        out: list[SecuritySnaresAlert] = []
        for raw in raw_list:
            try:
                alert = SecuritySnaresAlert.model_validate(raw)
            except Exception as e:
                logger.warning("skip_invalid_alert", error=str(e))
                continue
            if not _is_ransomware_alert(
                alert.ai_analysis,
                min_severity=self._settings.ransomware_min_severity,
                keyword=self._settings.ransomware_keyword,
            ):
                continue
            out.append(alert)
        return out

    def to_normalized(self, alert: SecuritySnaresAlert) -> NormalizedAlert | None:
        if not alert.entity_id or not alert.hostname or not alert.executing_username:
            return None
        account, domain = parse_executing_username(alert.executing_username)
        if not account:
            return None
        ai = parse_ai_analysis_field(alert.ai_analysis)
        return NormalizedAlert(
            entity_id=alert.entity_id,
            hostname=alert.hostname,
            executing_username_raw=alert.executing_username,
            hostname_normalized=normalize_hostname(alert.hostname),
            account_name=account,
            domain_hint=domain,
            alert_time=alert.alert_time,
            process_name=alert.process_name,
            process_sha256=alert.process_sha256,
            ai_summary=ai.summary,
            ai_severity=ai.severity,
            raw=alert.model_dump(mode="json", by_alias=True),
        )
