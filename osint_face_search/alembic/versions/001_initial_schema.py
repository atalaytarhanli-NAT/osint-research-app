"""Initial schema - cases, identities, audit_logs

Revision ID: 001_initial
Revises:
Create Date: 2026-05-02

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    case_status = sa.Enum(
        "OPEN", "IN_PROGRESS", "CLOSED", "ARCHIVED",
        name="casestatus",
    )
    identity_type = sa.Enum(
        "PERSONNEL", "WATCHLIST", "INCIDENT", "UNKNOWN",
        name="identitytype",
    )
    audit_action = sa.Enum(
        "SEARCH_PERFORMED", "IDENTITY_CREATED", "IDENTITY_DELETED",
        "CASE_CREATED", "CASE_UPDATED", "EXPORT_PERFORMED",
        name="auditaction",
    )

    case_status.create(op.get_bind(), checkfirst=True)
    identity_type.create(op.get_bind(), checkfirst=True)
    audit_action.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "cases",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("case_number", sa.String(50), nullable=False, unique=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("status", case_status, nullable=False, server_default="OPEN"),
        sa.Column("legal_basis", sa.String(500), nullable=False),
        sa.Column("created_by", sa.String(100), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("closed_at", sa.DateTime()),
    )
    op.create_index("ix_cases_case_number", "cases", ["case_number"])

    op.create_table(
        "identities",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("external_ref", sa.String(100), index=True),
        sa.Column("identity_type", identity_type, nullable=False),
        sa.Column("display_name", sa.String(200), nullable=False),
        sa.Column("notes", sa.Text()),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("qdrant_point_id", sa.String(100), nullable=False, unique=True),
        sa.Column("created_by", sa.String(100), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_identities_identity_type", "identities", ["identity_type"])
    op.create_index("ix_identities_qdrant_point_id", "identities", ["qdrant_point_id"])

    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("case_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("cases.id"), index=True),
        sa.Column("actor", sa.String(100), nullable=False, index=True),
        sa.Column("action", audit_action, nullable=False, index=True),
        sa.Column("resource_type", sa.String(50), nullable=False),
        sa.Column("resource_id", sa.String(100)),
        sa.Column("ip_address", sa.String(45)),
        sa.Column("user_agent", sa.String(500)),
        sa.Column("details", postgresql.JSON(), nullable=False, server_default="{}"),
        sa.Column("timestamp", sa.DateTime(), nullable=False,
                  server_default=sa.func.now(), index=True),
    )


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("identities")
    op.drop_table("cases")
    sa.Enum(name="auditaction").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="identitytype").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="casestatus").drop(op.get_bind(), checkfirst=True)
