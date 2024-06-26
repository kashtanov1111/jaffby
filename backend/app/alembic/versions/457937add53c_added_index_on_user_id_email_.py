"""added index on user_id email_confirmation_token table

Revision ID: 457937add53c
Revises: 44e125d5e34a
Create Date: 2024-03-25 11:57:11.032464

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '457937add53c'
down_revision: Union[str, None] = '44e125d5e34a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_index(op.f('ix_email_confirmation_tokens_user_id'), 'email_confirmation_tokens', ['user_id'], unique=False)
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_email_confirmation_tokens_user_id'), table_name='email_confirmation_tokens')
    # ### end Alembic commands ###
