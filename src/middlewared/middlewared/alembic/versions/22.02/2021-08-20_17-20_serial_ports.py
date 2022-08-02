"""
User serial port(s) name instead of I/O address

Revision ID: 725b7264abe6
Revises: 29abd3dce632
Create Date: 2021-20-08 17:20:42.818433+00:00
"""
from alembic import op
import sqlalchemy as sa

from middlewared.utils import osc


revision = '725b7264abe6'
down_revision = '29abd3dce632'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    io_choices = {e['start']: e['name'] for e in osc.system.serial_port_choices()}
    sys_config = [dict(row) for row in conn.execute("SELECT * FROM system_advanced").fetchall()]
    if not sys_config:
        return

    sys_config = sys_config[0]
    new_val = io_choices.get(sys_config['adv_serialport'], 'ttyS0')
    conn.execute("UPDATE system_advanced SET adv_serialport = ? WHERE id = ?", (new_val, sys_config['id']))


def downgrade():
    pass
