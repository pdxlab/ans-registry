"""rescale agent.trust_score from the legacy 1-10 ladder to the 0-100 TrustScore

The registry now scores on the platform-wide 0-100 TrustScore scale (the same
scale the gateway Trust Index and AgentCert surfaces use); ``calculate_trust_score``
was updated to match. This migration brings existing rows onto the new scale so
old registrations don't render as near-zero (e.g. ``7 / 100``) beside new ones.

Rescale is ``score * 10`` capped at 100. The tier boundaries scale identically
(8.0 -> 80 is still "Highly Trusted"), so ``trust_tier`` stays valid; we recompute
it from the new score anyway so there is no chance of drift. Guarded on
``trust_score <= 10`` so an already-0-100 row is never touched — and Alembic runs
this exactly once regardless.

Revision ID: 0004_rescale_trust_score_0_100
Revises: 0003_widen_ans_name
Create Date: 2026-09-20
"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004_rescale_trust_score_0_100"
down_revision: Union[str, None] = "0003_widen_ans_name"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Rescale legacy 1-10 scores to 0-100 (cap at 100), then recompute the tier
    # from the new score so the label always matches the number.
    op.execute(
        """
        UPDATE agent
           SET trust_score = LEAST(100, ROUND(trust_score * 10)),
               trust_tier = CASE
                   WHEN LEAST(100, ROUND(trust_score * 10)) >= 80 THEN 'Highly Trusted'
                   WHEN LEAST(100, ROUND(trust_score * 10)) >= 60 THEN 'Generally Safe'
                   WHEN LEAST(100, ROUND(trust_score * 10)) >= 40 THEN 'Use With Caution'
                   ELSE 'High Risk'
               END
         WHERE trust_score IS NOT NULL
           AND trust_score <= 10
        """
    )


def downgrade() -> None:
    # Best-effort reverse: divide back to the 1-10 ladder with its old tiers.
    op.execute(
        """
        UPDATE agent
           SET trust_score = ROUND((trust_score / 10.0)::numeric, 1),
               trust_tier = CASE
                   WHEN trust_score / 10.0 >= 8.0 THEN 'Highly Trusted'
                   WHEN trust_score / 10.0 >= 6.0 THEN 'Generally Safe'
                   WHEN trust_score / 10.0 >= 4.0 THEN 'Use With Caution'
                   ELSE 'High Risk'
               END
         WHERE trust_score IS NOT NULL
           AND trust_score > 10
        """
    )
