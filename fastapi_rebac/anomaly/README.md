# Suspicious activity MVP

The anomaly module is optional. It reads immutable `AuditLog` rows, aggregates them into user activity windows, runs enabled detectors, and stores results in `SuspiciousAlert`.

Minimal application setup:

```python
from fastapi_rebac import FastAPIReBAC
from fastapi_rebac.anomaly import SuspiciousActivityConfig

rebac = FastAPIReBAC(
    get_user_manager,
    auth_backends,
    get_async_session=get_async_session,
    audit_enabled=True,
    suspicious_activity_config=SuspiciousActivityConfig(
        enabled=True,
        rules_enabled=True,
        pyod_enabled=True,
        window_minutes=60,
        many_denied_threshold=10,
        bulk_read_threshold=100,
    ),
)
```

Optional PyOD dependency:

```bash
pip install fastapi-rebac[anomaly]
```

Manual/programmatic run:

```python
from fastapi_rebac.anomaly import run_suspicious_activity_detection

alerts = await run_suspicious_activity_detection(
    session,
    config=rebac.suspicious_activity_config,
)
```

Admin run:

Mount the admin panel and open **Administration → Suspicious alerts**. Superusers can press **Run detection**. The button uses the same configured `SuspiciousActivityConfig`.

The MVP does not block users and does not modify `AuditLog`; it only creates rows in `suspicious_alert`.


## Where PyOD is used

PyOD is used only inside the optional detector:

```text
fastapi_rebac/anomaly/service.py
  → run_suspicious_activity_detection()
  → detect_pyod_alerts()

fastapi_rebac/anomaly/pyod_detector.py
  → from pyod.models.ecod import ECOD
```

The import happens lazily during detection, so applications that do not install the `anomaly` extra can still use the rule-based detector and the rest of the library.
