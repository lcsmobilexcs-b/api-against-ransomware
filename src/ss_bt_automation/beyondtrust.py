"""BeyondTrust Password Safe Public API: session, managed account lookup, rotation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx
import structlog

from ss_bt_automation.config import Settings
from ss_bt_automation.http_utils import with_http_retries

logger = structlog.get_logger(__name__)


def _ps_auth_header(settings: Settings) -> str:
    parts = [f"PS-Auth key={settings.beyondtrust_api_key}", f"runas={settings.beyondtrust_runas}"]
    if settings.beyondtrust_password:
        parts.append(f"pwd=[{settings.beyondtrust_password}]")
    return "; ".join(parts) + ";"


@dataclass
class ManagedAccountMatch:
    account_id: int
    system_name: str | None
    account_name: str | None
    raw: dict[str, Any]


class BeyondTrustClient:
    """
    Maintains ASP.NET session via httpx cookie jar.

    Flow: SignAppIn -> ManagedAccounts lookup -> credentials/change -> Signout.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        base = settings.beyondtrust_base_url.rstrip("/")
        self._base = base
        self._auth = _ps_auth_header(settings)
        self._client: httpx.Client | None = None

    def __enter__(self) -> BeyondTrustClient:
        self._client = httpx.Client(
            base_url=self._base,
            headers={
                "Authorization": self._auth,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            timeout=self._settings.http_timeout_seconds,
            verify=self._settings.beyondtrust_verify_tls,
        )
        self._sign_in()
        return self

    def __exit__(self, *args: Any) -> None:
        if self._client:
            try:
                self._sign_out()
            except Exception as e:
                logger.warning("beyondtrust_signout_failed", error=str(e))
            self._client.close()
            self._client = None

    def _request(self) -> httpx.Client:
        if not self._client:
            raise RuntimeError("BeyondTrustClient not entered")
        return self._client

    def _sign_in(self) -> None:
        def _do() -> None:
            c = self._request()
            r = c.post("/Auth/SignAppin", content="")
            r.raise_for_status()

        with_http_retries(_do, max_attempts=self._settings.max_retries)()

    def _sign_out(self) -> None:
        c = self._request()
        r = c.post("/Auth/Signout", content="")
        if r.status_code not in (200, 204):
            r.raise_for_status()

    def find_managed_account(
        self,
        system_name: str,
        account_name: str,
    ) -> ManagedAccountMatch | None:
        """
        GET /ManagedAccounts?systemName=&accountName=

        Returns single match or None if 404.
        """

        def _do() -> httpx.Response:
            c = self._request()
            return c.get(
                "/ManagedAccounts",
                params={
                    "systemName": system_name,
                    "accountName": account_name,
                },
            )

        resp = with_http_retries(_do, max_attempts=self._settings.max_retries)()
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict):
            return self._to_match(data)
        if isinstance(data, list) and len(data) == 1:
            return self._to_match(data[0])
        if isinstance(data, list) and len(data) == 0:
            return None
        raise ValueError(f"Unexpected ManagedAccounts response shape: {type(data)}")

    def find_managed_account_by_account_name(self, account_name: str) -> list[ManagedAccountMatch]:
        def _do() -> httpx.Response:
            c = self._request()
            return c.get(
                "/ManagedAccounts",
                params={"accountName": account_name, "limit": 1000},
            )

        resp = with_http_retries(_do, max_attempts=self._settings.max_retries)()
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict):
            return [self._to_match(data)]
        if isinstance(data, list):
            return [self._to_match(x) for x in data if isinstance(x, dict)]
        return []

    @staticmethod
    def _to_match(obj: dict[str, Any]) -> ManagedAccountMatch:
        account_id = int(obj["AccountId"])
        return ManagedAccountMatch(
            account_id=account_id,
            system_name=obj.get("SystemName"),
            account_name=obj.get("AccountName"),
            raw=obj,
        )

    def change_credentials(self, managed_account_id: int) -> None:
        """
        POST /managedaccounts/{id}/credentials/change

        Base path already includes .../v3 so path is /managedaccounts/...
        """

        body = {
            "UpdateSystem": self._settings.credential_change_update_system,
            "Queue": self._settings.credential_change_queue,
        }

        def _do() -> None:
            c = self._request()
            r = c.post(
                f"/managedaccounts/{managed_account_id}/credentials/change",
                content=json.dumps(body),
            )
            if r.status_code == 204:
                return
            if r.status_code >= 400:
                try:
                    msg = r.json()
                except Exception:
                    msg = r.text
                raise httpx.HTTPStatusError(
                    f"Credential change failed: {msg}",
                    request=r.request,
                    response=r,
                )

        with_http_retries(_do, max_attempts=self._settings.max_retries)()
