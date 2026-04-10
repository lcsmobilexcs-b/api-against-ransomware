"""Scheduler entrypoint: poll SecuritySnares and orchestrate BeyondTrust actions."""

from __future__ import annotations

import argparse
import logging
import sys
import time

import structlog
from apscheduler.schedulers.background import BackgroundScheduler

from ss_bt_automation.circuit_breaker import CircuitBreaker
from ss_bt_automation.config import get_settings
from ss_bt_automation.metrics import Metrics
from ss_bt_automation.orchestrator import poll_and_process
from ss_bt_automation.store import StateStore


def configure_logging(level: str) -> None:
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper(), logging.INFO),
    )
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=False,
    )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SecuritySnares ransomware alerts -> BeyondTrust Password Safe rotation.",
    )
    parser.add_argument(
        "--company-domain",
        "-d",
        dest="company_domain_override",
        default=argparse.SUPPRESS,
        metavar="DOMAIN",
        help=(
            "Company DNS domain for FQDN managed-account lookup (e.g. contoso.com). "
            "Overrides COMPANY_DOMAIN from the environment when set."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    settings = get_settings()
    if hasattr(args, "company_domain_override"):
        settings = settings.model_copy(
            update={"company_domain": args.company_domain_override.strip()},
        )
    configure_logging(settings.log_level)
    log = structlog.get_logger("main")

    if not settings.securitysnares_api_key:
        log.error("missing_securitysnares_api_key")
        sys.exit(2)
    if not settings.beyondtrust_api_key or not settings.beyondtrust_runas:
        log.error("missing_beyondtrust_credentials")
        sys.exit(2)

    store = StateStore(settings.state_db_path)
    metrics = Metrics()
    circuit = CircuitBreaker(
        settings.circuit_failure_threshold,
        settings.circuit_cooldown_seconds,
    )

    def job() -> None:
        t0 = time.monotonic()
        try:
            poll_and_process(settings, store, metrics, circuit)
        finally:
            dt = time.monotonic() - t0
            log.info(
                "poll_cycle_done",
                duration_s=round(dt, 3),
                metrics=metrics.snapshot(),
                circuit=circuit.state(),
                store=store.stats(),
            )

    job()

    sched = BackgroundScheduler()
    sched.add_job(
        job,
        "interval",
        seconds=settings.securitysnares_poll_seconds,
        max_instances=1,
        coalesce=True,
        jitter=5,
    )
    sched.start()
    log.info(
        "scheduler_started",
        poll_seconds=settings.securitysnares_poll_seconds,
        state_db=settings.state_db_path,
        company_domain=settings.company_domain or None,
    )

    try:
        while True:
            time.sleep(3600)
    except (KeyboardInterrupt, SystemExit):
        sched.shutdown(wait=False)
        log.info("shutdown")


if __name__ == "__main__":
    main()
