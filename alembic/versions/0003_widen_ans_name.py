"""widen agent.ans_name for ANS v2 names (TRUS-1550)

ANS v2 names are DNS-anchored and owner-domain-qualified —
``ans://v<semver>.<host>`` — which is longer than the legacy 3-63 char label.
Widen ``agent.ans_name`` from VARCHAR(100) to VARCHAR(300) so v2 names fit.

Low risk: the registry holds only dev/test rows pre-launch (see
0002_purge_dev_test_data), and this widens the column without touching data.

Revision ID: 0003_widen_ans_name
Revises: 0002_purge_dev_test_data
Create Date: 2026-07-29
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003_widen_ans_name"
down_revision: Union[str, None] = "0002_purge_dev_test_data"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "agent",
        "ans_name",
        existing_type=sa.String(length=100),
        type_=sa.String(length=300),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "agent",
        "ans_name",
        existing_type=sa.String(length=300),
        type_=sa.String(length=100),
        existing_nullable=False,
    )
