"""Replication readonly

Revision ID: 8f874e6e40bc
Revises: b5cac06345ea
Create Date: 2020-03-10 09:03:42.449016+00:00

"""
import os

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8f874e6e40bc'
down_revision = 'b5cac06345ea'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    conn = op.get_bind()
    for column in conn.execute("PRAGMA TABLE_INFO(storage_replication)"):
        if column["name"] == "repl_readonly":
            return

    readonly = "REQUIRE" if os.path.exists("/data/license") else "SET"

    with op.batch_alter_table('storage_replication', schema=None) as batch_op:
        batch_op.add_column(sa.Column('repl_readonly', sa.String(length=120), nullable=False, default=readonly))
        batch_op.alter_column('repl_readonly',
               existing_type=sa.TEXT(),
               server_default=None)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('storage_replication', schema=None) as batch_op:
        batch_op.drop_column('repl_readonly')

    # ### end Alembic commands ###
