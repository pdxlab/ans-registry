"""purge dev/test data from the ANS registry

One-time cleanup of records accumulated during local + QA smoke-testing of
the gateway proxy and the ANS console (TRUS-1283). Truncates the four data
tables — `agent`, `transfer`, `lookuplog`, `a2averificationlog` — and leaves
the admin tables (`adminuser`, `adminsession`) intact.

Pre-launch, the registry has no real customer data, so this is a flat wipe
rather than a selective DELETE WHERE. After this revision applies on each
environment, fresh registrations from the production gateway will populate
the registry cleanly.

Idempotent — re-running against an empty table is a no-op.

Revision ID: 0002_purge_dev_test_data
Revises: 0001_initial
Create Date: 2026-06-19
"""

from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "0002_purge_dev_test_data"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Order matters only if there were real FKs between these tables; today they
# reference by string ans_name, not FK. We still order child → parent so a
# future schema change adding FKs doesn't surprise this migration.
_TABLES_TO_PURGE = (
    "a2averificationlog",
    "lookuplog",
    "transfer",
    "agent",
)


def upgrade() -> None:
    for table in _TABLES_TO_PURGE:
        op.execute(f"DELETE FROM {table};")


def downgrade() -> None:
    # Deleted data cannot be reconstructed — downgrade is a no-op by design.
    pass
