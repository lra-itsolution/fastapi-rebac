"""Add Yandex 2FA tables for example app.

Revision ID: 20260502_0002
Revises: 20260502_0001
Create Date: 2026-05-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260502_0002"
down_revision: str | None = "20260502_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

uuid_type = postgresql.UUID(as_uuid=True)


def upgrade() -> None:
    op.create_table(
        "rebac_yandex_second_factor",
        sa.Column("id", uuid_type, nullable=False),
        sa.Column("user_id", uuid_type, nullable=False),
        sa.Column("provider_subject", sa.String(length=255), nullable=False),
        sa.Column("yandex_login", sa.String(length=255), nullable=True),
        sa.Column("yandex_email", sa.String(length=320), nullable=True),
        sa.Column("yandex_psuid", sa.String(length=512), nullable=True),
        sa.Column("is_enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("provider_subject", name="uq_rebac_yandex_second_factor_provider_subject"),
        sa.UniqueConstraint("user_id", name="uq_rebac_yandex_second_factor_user_id"),
    )
    op.create_index(
        "ix_rebac_yandex_second_factor_user_id",
        "rebac_yandex_second_factor",
        ["user_id"],
    )
    op.create_index(
        "ix_rebac_yandex_second_factor_user_enabled",
        "rebac_yandex_second_factor",
        ["user_id", "is_enabled"],
    )

    op.create_table(
        "rebac_yandex_pre_auth_session",
        sa.Column("id", uuid_type, nullable=False),
        sa.Column("user_id", uuid_type, nullable=False),
        sa.Column("state", sa.String(length=255), nullable=False),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("code_verifier", sa.String(length=255), nullable=True),
        sa.Column("redirect_after", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("state", name="uq_rebac_yandex_pre_auth_state"),
    )
    op.create_index(
        "ix_rebac_yandex_pre_auth_session_user_id",
        "rebac_yandex_pre_auth_session",
        ["user_id"],
    )
    op.create_index(
        "ix_rebac_yandex_pre_auth_session_state",
        "rebac_yandex_pre_auth_session",
        ["state"],
    )
    op.create_index(
        "ix_rebac_yandex_pre_auth_session_purpose",
        "rebac_yandex_pre_auth_session",
        ["purpose"],
    )
    op.create_index(
        "ix_rebac_yandex_pre_auth_session_expires_at",
        "rebac_yandex_pre_auth_session",
        ["expires_at"],
    )
    op.create_index(
        "ix_rebac_yandex_pre_auth_user_purpose",
        "rebac_yandex_pre_auth_session",
        ["user_id", "purpose"],
    )


def downgrade() -> None:
    op.drop_index("ix_rebac_yandex_pre_auth_user_purpose", table_name="rebac_yandex_pre_auth_session")
    op.drop_index("ix_rebac_yandex_pre_auth_session_expires_at", table_name="rebac_yandex_pre_auth_session")
    op.drop_index("ix_rebac_yandex_pre_auth_session_purpose", table_name="rebac_yandex_pre_auth_session")
    op.drop_index("ix_rebac_yandex_pre_auth_session_state", table_name="rebac_yandex_pre_auth_session")
    op.drop_index("ix_rebac_yandex_pre_auth_session_user_id", table_name="rebac_yandex_pre_auth_session")
    op.drop_table("rebac_yandex_pre_auth_session")

    op.drop_index("ix_rebac_yandex_second_factor_user_enabled", table_name="rebac_yandex_second_factor")
    op.drop_index("ix_rebac_yandex_second_factor_user_id", table_name="rebac_yandex_second_factor")
    op.drop_table("rebac_yandex_second_factor")
