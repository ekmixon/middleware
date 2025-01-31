import logging
import os
import base64
import subprocess
import contextlib

from middlewared.utils import Popen

logger = logging.getLogger(__name__)
kdir = "/etc/kerberos"
keytabfile = "/etc/krb5.keytab"
ktutil_cmd = "ktutil"


async def mit_copy(temp_keytab):
    kt_copy = await Popen(['ktutil'],
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,
                          stdin=subprocess.PIPE)
    output = await kt_copy.communicate(
        f'rkt {temp_keytab}\nwkt /etc/mit_tmp.keytab'.encode()
    )
    if output[1]:
        logger.debug(f"failed to generate [{keytabfile}]: {output[1].decode()}")


async def write_keytab(db_keytabname, db_keytabfile):
    temp_keytab = f'{kdir}/{db_keytabname}'
    if not os.path.exists(kdir):
        os.mkdir(kdir)
    if os.path.exists(temp_keytab):
        os.remove(temp_keytab)
    with open(temp_keytab, "wb") as f:
        f.write(db_keytabfile)

    await mit_copy(temp_keytab)
    os.remove(temp_keytab)


async def render(service, middleware):
    keytabs = await middleware.call('kerberos.keytab.query')
    if not keytabs:
        logger.trace('No keytabs in configuration database, skipping keytab generation')
        return

    for keytab in keytabs:
        db_keytabfile = base64.b64decode(keytab['file'].encode())
        db_keytabname = keytab['id']
        await write_keytab(db_keytabname, db_keytabfile)

    with contextlib.suppress(OSError):
        os.unlink(keytabfile)

    os.rename("/etc/mit_tmp.keytab", keytabfile)
