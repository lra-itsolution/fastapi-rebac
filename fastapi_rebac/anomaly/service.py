from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.suspicious_alert import SuspiciousAlert
from .config import SuspiciousActivityConfig
from .feature_builder import (
    ActivityWindowFeatures,
    load_activity_window_features,
)
from .pyod_detector import detect_pyod_alerts
from .rules import SuspiciousAlertCandidate, detect_rule_alerts


async def save_alert_candidates(
    session: AsyncSession,
    candidates: Sequence[SuspiciousAlertCandidate],
    *,
    skip_existing: bool = True,
    commit: bool = False,
) -> list[SuspiciousAlert]:
    """Persist detector candidates to suspicious_alert.

    By default the function avoids duplicate alerts with the same detector,
    rule, actor and time window. This makes repeated manual runs safe enough
    for the MVP.
    """

    created: list[SuspiciousAlert] = []
    for candidate in candidates:
        if skip_existing:
            existing_stmt = (
                select(SuspiciousAlert.id)
                .where(SuspiciousAlert.detector_type == candidate.detector_type)
                .where(SuspiciousAlert.rule_key == candidate.rule_key)
                .where(SuspiciousAlert.actor_id == candidate.actor_id)
                .where(SuspiciousAlert.window_start == candidate.window_start)
                .where(SuspiciousAlert.window_end == candidate.window_end)
                .limit(1)
            )
            existing = (await session.execute(existing_stmt)).scalar_one_or_none()
            if existing is not None:
                continue

        alert = SuspiciousAlert(
            actor_id=candidate.actor_id,
            detector_type=candidate.detector_type,
            rule_key=candidate.rule_key,
            severity=candidate.severity,
            score=candidate.score,
            description=candidate.description,
            window_start=candidate.window_start,
            window_end=candidate.window_end,
            audit_log_ids=candidate.audit_log_ids,
            payload=candidate.payload,
        )
        session.add(alert)
        created.append(alert)

    if commit and created:
        await session.commit()
        for alert in created:
            await session.refresh(alert)

    return created


def _resolve_window(
    config: SuspiciousActivityConfig,
    *,
    window_start: datetime | None,
    window_end: datetime | None,
) -> tuple[datetime, datetime]:
    if window_end is None:
        window_end = datetime.now(timezone.utc)
    if window_start is None:
        window_start = window_end - timedelta(minutes=config.window_minutes)
    return window_start, window_end


async def _load_features_for_config(
    session: AsyncSession,
    config: SuspiciousActivityConfig,
    *,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
) -> list[ActivityWindowFeatures]:
    window_start, window_end = _resolve_window(
        config,
        window_start=window_start,
        window_end=window_end,
    )
    return await load_activity_window_features(
        session,
        window_start=window_start,
        window_end=window_end,
        window_minutes=config.window_minutes,
        night_start_hour=config.night_start_hour,
        night_end_hour=config.night_end_hour,
    )


async def run_suspicious_activity_rules(
    session: AsyncSession,
    *,
    config: SuspiciousActivityConfig | None = None,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    commit: bool = True,
) -> list[SuspiciousAlert]:
    """Run only the rule-based MVP detector for one audit window and save alerts."""

    cfg = config or SuspiciousActivityConfig(enabled=True)
    if not cfg.enabled or not cfg.rules_enabled:
        return []

    features = await _load_features_for_config(
        session,
        cfg,
        window_start=window_start,
        window_end=window_end,
    )
    candidates = detect_rule_alerts(features, config=cfg)
    return await save_alert_candidates(session, candidates, commit=commit)


async def run_suspicious_activity_pyod(
    session: AsyncSession,
    *,
    config: SuspiciousActivityConfig | None = None,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    commit: bool = True,
) -> list[SuspiciousAlert]:
    """Run only the optional PyOD ECOD detector and save alerts."""

    cfg = config or SuspiciousActivityConfig(enabled=True)
    if not cfg.enabled or not cfg.pyod_enabled:
        return []

    features = await _load_features_for_config(
        session,
        cfg,
        window_start=window_start,
        window_end=window_end,
    )
    candidates = detect_pyod_alerts(features, config=cfg)
    return await save_alert_candidates(session, candidates, commit=commit)


async def run_suspicious_activity_detection(
    session: AsyncSession,
    *,
    config: SuspiciousActivityConfig | None = None,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    commit: bool = True,
) -> list[SuspiciousAlert]:
    """Run all enabled MVP detectors for one audit window and save alerts.

    Current MVP detectors:
    - rule-based checks for obvious suspicious activity;
    - optional PyOD ECOD outlier detection on the same aggregated features.
    """

    cfg = config or SuspiciousActivityConfig(enabled=True)
    if not cfg.enabled:
        return []

    features = await _load_features_for_config(
        session,
        cfg,
        window_start=window_start,
        window_end=window_end,
    )

    candidates: list[SuspiciousAlertCandidate] = []
    if cfg.rules_enabled:
        candidates.extend(detect_rule_alerts(features, config=cfg))
    if cfg.pyod_enabled:
        candidates.extend(detect_pyod_alerts(features, config=cfg))

    return await save_alert_candidates(session, candidates, commit=commit)


async def build_suspicious_activity_rule_candidates(
    session: AsyncSession,
    *,
    config: SuspiciousActivityConfig | None = None,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
) -> tuple[list[ActivityWindowFeatures], list[SuspiciousAlertCandidate]]:
    """Build features and rule candidates without saving them.

    Useful for tests, previews and future admin UI endpoints.
    """

    cfg = config or SuspiciousActivityConfig(enabled=True)
    features = await _load_features_for_config(
        session,
        cfg,
        window_start=window_start,
        window_end=window_end,
    )
    return features, detect_rule_alerts(features, config=cfg)


async def build_suspicious_activity_candidates(
    session: AsyncSession,
    *,
    config: SuspiciousActivityConfig | None = None,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
) -> tuple[list[ActivityWindowFeatures], list[SuspiciousAlertCandidate]]:
    """Build features and all enabled detector candidates without saving them."""

    cfg = config or SuspiciousActivityConfig(enabled=True)
    features = await _load_features_for_config(
        session,
        cfg,
        window_start=window_start,
        window_end=window_end,
    )

    candidates: list[SuspiciousAlertCandidate] = []
    if cfg.rules_enabled:
        candidates.extend(detect_rule_alerts(features, config=cfg))
    if cfg.pyod_enabled:
        candidates.extend(detect_pyod_alerts(features, config=cfg))

    return features, candidates
