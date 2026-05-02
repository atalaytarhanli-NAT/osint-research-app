"""Add external_search_results table and EXTERNAL_SEARCH_PERFORMED enum

Revision ID: 002_external_search
Revises: 001_initial
Create Date: 2026-05-02

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "002_external_search"
down_revision = "001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Yeni enum değerini ekle (PostgreSQL ALTER TYPE ADD VALUE)
    op.execute(
        "ALTER TYPE auditaction ADD VALUE IF NOT EXISTS 'EXTERNAL_SEARCH_PERFORMED'"
    )

    op.create_table(
        "external_search_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("case_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("cases.id"), nullable=False, index=True),
        sa.Column("adapter_name", sa.String(50), nullable=False, index=True),
        sa.Column("data_residency", sa.String(10), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("error", sa.Text()),
        sa.Column("matches_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("elapsed_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cost_credits", sa.Float()),
        sa.Column("response_payload", postgresql.JSON(), nullable=False, server_default="{}"),
        sa.Column("queried_by", sa.String(100), nullable=False),
        sa.Column("queried_at", sa.DateTime(), nullable=False,
                  server_default=sa.func.now(), index=True),
    )


def downgrade() -> None:
    op.drop_table("external_search_results")
    # PostgreSQL enum'dan değer kaldırmak doğal değil — manuel migration gerekir
