"""Initial schema for fastapi-rebac example app.

Revision ID: 20260502_0001
Revises:
Create Date: 2026-05-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260502_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

uuid_type = postgresql.UUID(as_uuid=True)
action_enum = sa.Enum("CREATE", "READ", "UPDATE", "DELETE", name="rebac_action_enum", native_enum=False)
audit_status_enum = sa.Enum(
    "SUCCESS",
    "DENIED",
    "ERROR",
    name="rebac_audit_status_enum",
    native_enum=False,
)
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
        "user",
        sa.Column("id", uuid_type, nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("hashed_password", sa.String(length=1024), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("is_superuser", sa.Boolean(), nullable=False),
        sa.Column("is_verified", sa.Boolean(), nullable=False),
        sa.Column("username", sa.String(length=150), nullable=False),
        sa.Column("first_name", sa.String(length=150), nullable=True),
        sa.Column("last_name", sa.String(length=150), nullable=True),
        sa.Column("is_staff", sa.Boolean(), nullable=False),
        sa.Column("created_by_id", uuid_type, nullable=True),
        sa.Column("supervisor_id", uuid_type, nullable=True),
        *_timestamps(),
        sa.ForeignKeyConstraint(["created_by_id"], ["user.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["supervisor_id"], ["user.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_user_email", "user", ["email"], unique=True)
    op.create_index("ix_user_username", "user", ["username"], unique=True)
    op.create_index("ix_user_created_by_id", "user", ["created_by_id"])
    op.create_index("ix_user_supervisor_id", "user", ["supervisor_id"])

    op.create_table(
        "auth_table",
        sa.Column("id", uuid_type, nullable=False),
        sa.Column("key", sa.String(length=255), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=True),
        sa.Column("is_service", sa.Boolean(), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_auth_table_key", "auth_table", ["key"], unique=True)

    op.create_table(
        "note",
        sa.Column("id", uuid_type, nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("body", sa.Text(), nullable=True),
        sa.Column("created_by_id", uuid_type, nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["created_by_id"], ["user.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_note_created_by_id", "note", ["created_by_id"])

    op.create_table(
        "group",
        sa.Column("id", uuid_type, nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("created_by_id", uuid_type, nullable=False),
        sa.Column("share_members_visibility", sa.Boolean(), nullable=False),
        sa.Column("share_creator_visibility", sa.Boolean(), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["created_by_id"], ["user.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_group_created_by_id", "group", ["created_by_id"])
    op.create_index("ix_group_name", "group", ["name"], unique=True)

    op.create_table(
        "audit_log",
        sa.Column("id", uuid_type, nullable=False),
        sa.Column("actor_id", uuid_type, nullable=True),
        sa.Column("action", action_enum, nullable=False),
        sa.Column("table_key", sa.String(length=255), nullable=True),
        sa.Column("object_id", sa.String(length=255), nullable=True),
        sa.Column("status", audit_status_enum, nullable=False),
        sa.Column("client_ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("request_id", sa.String(length=255), nullable=True),
        sa.Column("meta", sa.JSON(), nullable=True),
        *_timestamps(),
        sa.ForeignKeyConstraint(["actor_id"], ["user.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_log_actor_id", "audit_log", ["actor_id"])
    op.create_index("ix_audit_log_object_id", "audit_log", ["object_id"])
    op.create_index("ix_audit_log_request_id", "audit_log", ["request_id"])
    op.create_index("ix_audit_log_table_key", "audit_log", ["table_key"])

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

    op.create_table(
        "group_membership",
        sa.Column("id", uuid_type, nullable=False),
        sa.Column("group_id", uuid_type, nullable=False),
        sa.Column("user_id", uuid_type, nullable=False),
        sa.Column("created_by_id", uuid_type, nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["created_by_id"], ["user.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["group_id"], ["group.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("group_id", "user_id", name="uq_group_membership_group_user"),
    )
    op.create_index("ix_group_membership_created_by_id", "group_membership", ["created_by_id"])
    op.create_index("ix_group_membership_group_id", "group_membership", ["group_id"])
    op.create_index("ix_group_membership_user_id", "group_membership", ["user_id"])

    op.create_table(
        "user_permission",
        sa.Column("id", uuid_type, nullable=False),
        sa.Column("user_id", uuid_type, nullable=False),
        sa.Column("table_id", uuid_type, nullable=False),
        sa.Column("action", action_enum, nullable=False),
        sa.Column("granted_by_id", uuid_type, nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["granted_by_id"], ["user.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["table_id"], ["auth_table.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "table_id", "action", name="uq_user_permission"),
    )
    op.create_index("ix_user_permission_granted_by_id", "user_permission", ["granted_by_id"])
    op.create_index("ix_user_permission_table_id", "user_permission", ["table_id"])
    op.create_index("ix_user_permission_user_id", "user_permission", ["user_id"])

    op.create_table(
        "group_permission",
        sa.Column("id", uuid_type, nullable=False),
        sa.Column("group_id", uuid_type, nullable=False),
        sa.Column("table_id", uuid_type, nullable=False),
        sa.Column("action", action_enum, nullable=False),
        sa.Column("granted_by_id", uuid_type, nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["granted_by_id"], ["user.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["group_id"], ["group.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["table_id"], ["auth_table.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("group_id", "table_id", "action", name="uq_group_permission"),
    )
    op.create_index("ix_group_permission_granted_by_id", "group_permission", ["granted_by_id"])
    op.create_index("ix_group_permission_group_id", "group_permission", ["group_id"])
    op.create_index("ix_group_permission_table_id", "group_permission", ["table_id"])


def downgrade() -> None:
    op.drop_index("ix_group_permission_table_id", table_name="group_permission")
    op.drop_index("ix_group_permission_group_id", table_name="group_permission")
    op.drop_index("ix_group_permission_granted_by_id", table_name="group_permission")
    op.drop_table("group_permission")

    op.drop_index("ix_user_permission_user_id", table_name="user_permission")
    op.drop_index("ix_user_permission_table_id", table_name="user_permission")
    op.drop_index("ix_user_permission_granted_by_id", table_name="user_permission")
    op.drop_table("user_permission")

    op.drop_index("ix_group_membership_user_id", table_name="group_membership")
    op.drop_index("ix_group_membership_group_id", table_name="group_membership")
    op.drop_index("ix_group_membership_created_by_id", table_name="group_membership")
    op.drop_table("group_membership")

    op.drop_index("ix_suspicious_alert_window_start", table_name="suspicious_alert")
    op.drop_index("ix_suspicious_alert_window_end", table_name="suspicious_alert")
    op.drop_index("ix_suspicious_alert_status", table_name="suspicious_alert")
    op.drop_index("ix_suspicious_alert_severity", table_name="suspicious_alert")
    op.drop_index("ix_suspicious_alert_rule_key", table_name="suspicious_alert")
    op.drop_index("ix_suspicious_alert_detector_type", table_name="suspicious_alert")
    op.drop_index("ix_suspicious_alert_actor_id", table_name="suspicious_alert")
    op.drop_table("suspicious_alert")

    op.drop_index("ix_audit_log_table_key", table_name="audit_log")
    op.drop_index("ix_audit_log_request_id", table_name="audit_log")
    op.drop_index("ix_audit_log_object_id", table_name="audit_log")
    op.drop_index("ix_audit_log_actor_id", table_name="audit_log")
    op.drop_table("audit_log")

    op.drop_index("ix_group_name", table_name="group")
    op.drop_index("ix_group_created_by_id", table_name="group")
    op.drop_table("group")

    op.drop_index("ix_note_created_by_id", table_name="note")
    op.drop_table("note")

    op.drop_index("ix_auth_table_key", table_name="auth_table")
    op.drop_table("auth_table")

    op.drop_index("ix_user_supervisor_id", table_name="user")
    op.drop_index("ix_user_created_by_id", table_name="user")
    op.drop_index("ix_user_username", table_name="user")
    op.drop_index("ix_user_email", table_name="user")
    op.drop_table("user")
