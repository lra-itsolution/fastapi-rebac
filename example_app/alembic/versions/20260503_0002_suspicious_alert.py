"""Add suspicious alert table.

Revision ID: 20260503_0002
Revises: 20260502_0001
Create Date: 2026-05-03
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260503_0002"
down_revision: str | None = "20260502_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

uuid_type = postgresql.UUID(as_uuid=True)
suspicious_severity_enum = sa.Enum(
    "LOW",
    "MEDIUM",
    "HIGH",
    name="rebac_suspicious_severity_enum",
    native_enum=False,
)
suspicious_status_enum = sa.Enum(
    "NEW",
    "REVIEWED",
    "FALSE_POSITIVE",
    "CONFIRMED",
    name="rebac_suspicious_status_enum",
    native_enum=False,
)


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    ]


def upgrade() -> None:
    op.create_table(
        "suspicious_alert",
        sa.Column("id", uuid_type, nullable=False),
        sa.Column("actor_id", uuid_type, nullable=True),
        sa.Column("detector_type", sa.String(length=32), nullable=False),
        sa.Column("rule_key", sa.String(length=100), nullable=False),
        sa.Column("severity", suspicious_severity_enum, nullable=False),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("status", suspicious_status_enum, nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("audit_log_ids", sa.JSON(), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=True),
        *_timestamps(),
        sa.ForeignKeyConstraint(["actor_id"], ["user.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_suspicious_alert_actor_id", "suspicious_alert", ["actor_id"])
    op.create_index("ix_suspicious_alert_detector_type", "suspicious_alert", ["detector_type"])
    op.create_index("ix_suspicious_alert_rule_key", "suspicious_alert", ["rule_key"])
    op.create_index("ix_suspicious_alert_severity", "suspicious_alert", ["severity"])
    op.create_index("ix_suspicious_alert_status", "suspicious_alert", ["status"])
    op.create_index("ix_suspicious_alert_window_end", "suspicious_alert", ["window_end"])
    op.create_index("ix_suspicious_alert_window_start", "suspicious_alert", ["window_start"])


def downgrade() -> None:
    op.drop_index("ix_suspicious_alert_window_start", table_name="suspicious_alert")
    op.drop_index("ix_suspicious_alert_window_end", table_name="suspicious_alert")
    op.drop_index("ix_suspicious_alert_status", table_name="suspicious_alert")
    op.drop_index("ix_suspicious_alert_severity", table_name="suspicious_alert")
    op.drop_index("ix_suspicious_alert_rule_key", table_name="suspicious_alert")
    op.drop_index("ix_suspicious_alert_detector_type", table_name="suspicious_alert")
    op.drop_index("ix_suspicious_alert_actor_id", table_name="suspicious_alert")
    op.drop_table("suspicious_alert")
