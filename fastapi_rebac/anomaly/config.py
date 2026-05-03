from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class SuspiciousActivityConfig:
    """Configuration for optional suspicious activity detection.

    The detector is disabled by default and can be enabled by an application
    only when audit logs are already collected.
    """

    enabled: bool = False
    rules_enabled: bool = True
    pyod_enabled: bool = True
    adtk_enabled: bool = False

    window_minutes: int = 60
    min_events_for_pyod: int = 20
    pyod_min_rows: int = 5
    pyod_contamination: float = 0.15

    many_denied_threshold: int = 10
    bulk_read_threshold: int = 100
    many_deletes_threshold: int = 10
    many_unique_objects_threshold: int = 50
    many_unique_ips_threshold: int = 3
    night_administration_actions_threshold: int = 1
    night_start_hour: int = 22
    night_end_hour: int = 6
