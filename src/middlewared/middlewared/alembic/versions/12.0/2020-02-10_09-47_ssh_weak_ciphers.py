"""SSH weak ciphers

Revision ID: 06bfbd354deb
Revises: 4abbf75347b2
Create Date: 2020-02-10 09:47:12.017225+00:00

"""
import json
import re

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '06bfbd354deb'
down_revision = '4abbf75347b2'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('services_ssh', schema=None) as batch_op:
        batch_op.add_column(sa.Column('ssh_weak_ciphers', sa.TEXT(), nullable=True))

    conn = op.get_bind()
    for row in conn.execute("SELECT * FROM services_ssh").fetchall():
        row = dict(row)

        ssh_weak_ciphers = ['AES128-CBC', 'NONE']

        if m := re.search(
            'NoneEnabled\s+(yes|no)', row['ssh_options'], flags=re.IGNORECASE
        ):
            row['ssh_options'] = row['ssh_options'].replace(m[0], '')
            if m[1].lower() == 'no':
                ssh_weak_ciphers.remove('NONE')

        if 'Ciphers' in row['ssh_options']:
            ssh_weak_ciphers.remove('AES128-CBC')

        conn.execute("UPDATE services_ssh SET ssh_weak_ciphers = :ssh_weak_ciphers, "
                     "ssh_options = :ssh_options WHERE id = :id",
                     ssh_weak_ciphers=json.dumps(ssh_weak_ciphers),
                     ssh_options=row["ssh_options"],
                     id=row["id"])

    with op.batch_alter_table('services_ssh', schema=None) as batch_op:
        batch_op.alter_column('ssh_weak_ciphers',
               existing_type=sa.TEXT(),
               nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('services_ssh', schema=None) as batch_op:
        batch_op.drop_column('ssh_weak_ciphers')

    # ### end Alembic commands ###
