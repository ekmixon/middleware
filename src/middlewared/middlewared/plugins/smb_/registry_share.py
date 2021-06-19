from middlewared.service import private, Service, filterable
from middlewared.service_exception import CallError
from middlewared.utils import run, filter_list
from middlewared.plugins.smb import SMBCmd, SMBHAMODE, SMBSharePreset
from middlewared.utils import osc

import errno
import json

FRUIT_CATIA_MAPS = [
    "0x01:0xf001,0x02:0xf002,0x03:0xf003,0x04:0xf004",
    "0x05:0xf005,0x06:0xf006,0x07:0xf007,0x08:0xf008",
    "0x09:0xf009,0x0a:0xf00a,0x0b:0xf00b,0x0c:0xf00c",
    "0x0d:0xf00d,0x0e:0xf00e,0x0f:0xf00f,0x10:0xf010",
    "0x11:0xf011,0x12:0xf012,0x13:0xf013,0x14:0xf014",
    "0x15:0xf015,0x16:0xf016,0x17:0xf017,0x18:0xf018",
    "0x19:0xf019,0x1a:0xf01a,0x1b:0xf01b,0x1c:0xf01c",
    "0x1d:0xf01d,0x1e:0xf01e,0x1f:0xf01f",
    "0x22:0xf020,0x2a:0xf021,0x3a:0xf022,0x3c:0xf023",
    "0x3e:0xf024,0x3f:0xf025,0x5c:0xf026,0x7c:0xf027"
]

DEFAULT_SHARE_PARAMETERS = {
    "purpose": {"smbconf": "tn:purpose", "default": ""},
    "path": {"smbconf": "path", "default": ""},
    "path_suffix": {"smbconf": "tn:path_suffix", "default": ""},
    "guestok": {"smbconf": "guest ok", "default": False},
    "browsable": {"smbconf": "browseable", "default": True},
    "hostsallow": {"smbconf": "hosts allow", "default": []},
    "hostsdeny": {"smbconf": "hosts deny", "default": []},
    "abe": {"smbconf": "access based share enumeration", "default": False},
    "ro": {"smbconf": "read only", "default": True},
    "durable handle": {"smbconf": "posix locking", "default": True},
    "cluster_volname": {"smbconf": "glusterfs: volume", "default": ""},
}

CONF_JSON_VERSION = {"major": 0, "minor": 1}


class SharingSMBService(Service):

    class Config:
        namespace = 'sharing.smb'

    @private
    async def json_check_version(self, version):
        if version == CONF_JSON_VERSION:
            return

        raise CallError(
            "Unexpected JSON version returned from Samba utils: "
            f"[{version}]. Expected version was: [{CONF_JSON_VERSION}]. "
            "Behavior is undefined with a version mismatch and so refusing "
            "to perform groupmap operation. Please file a bug report at "
            "jira.ixsystems.com with this traceback."
        )

    @private
    async def netconf(self, **kwargs):
        """
        wrapper for net(8) conf. This manages the share configuration, which is stored in
        samba's registry.tdb file.
        """
        action = kwargs.get('action')
        if action not in [
            'list',
            'showshare',
            'addshare',
            'delshare',
            'getparm',
            'setparm',
            'delparm'
        ]:
            raise CallError(f'Action [{action}] is not permitted.', errno.EPERM)

        ha_mode = SMBHAMODE[(await self.middleware.call('smb.get_smb_ha_mode'))]
        if ha_mode == SMBHAMODE.CLUSTERED:
            ctdb_healthy = await self.middleware.call('ctdb.general.healthy')
            if not ctdb_healthy:
                raise CallError(
                    "Registry calls not permitted when ctdb unhealthy.", errno.ENXIO
                )

        share = kwargs.get('share')
        args = kwargs.get('args', [])
        jsoncmd = kwargs.get('jsoncmd', False)
        if jsoncmd:
            cmd = [SMBCmd.NET.value, '--json', 'conf', action]
        else:
            cmd = [SMBCmd.NET.value, 'conf', action]

        if share:
            cmd.append(share)

        if args:
            cmd.extend(args)

        netconf = await run(cmd, check=False)
        if netconf.returncode != 0:
            if action != 'getparm':
                self.logger.debug('netconf failure for command [%s] stdout: %s',
                                  cmd, netconf.stdout.decode())
            raise CallError(
                f'net conf {action} [{share}] failed with error: {netconf.stderr.decode()}'
            )

        if jsoncmd:
            out = netconf.stdout.decode()
            try:
                out = json.loads(out)
            except json.JSONDecodeError:
                self.logger.debug("XXX: %s", netconf.stdout.decode())
        else:
            out = netconf.stdout.decode()

        return out

    @private
    async def reg_listshares(self):
        out = []
        res = await self.netconf(action='list', jsoncmd=True)
        version = res.pop('version')
        await self.json_check_version(version)

        for s in res['sections']:
            if s['is_share']:
                out.append(s['service'])

        return out

    @private
    async def reg_list(self):
        res = await self.netconf(action='list', jsoncmd=True)
        version = res.pop('version')
        await self.json_check_version(version)

        return res

    @private
    async def smbconf_to_payload(self, conf):
        out = {}
        for k, v in conf.items():
            out[k] = {"raw": v}

        return out

    @private
    async def reg_addshare(self, data):
        conf = await self.share_to_smbconf(data)
        name = 'homes' if data['home'] else data['name']
        parsed = await self.smbconf_to_payload(conf)

        payload = {
            "service": name,
            "parameters": conf,
        }
        await self.netconf(
            action='addshare',
            jsoncmd=True,
            args=[json.dumps(payload)]
        )

    @private
    async def reg_delshare(self, share):
        return await self.netconf(action='delshare', share=share)

    @private
    async def reg_showshare(self, share):
        out = []
        net = await self.netconf(action='showshare', share=share, jsoncmd=True)
        version = net.pop('version')
        await self.json_check_version(version)

        to_list = ['vfs objects', 'hosts allow', 'hosts deny']
        parameters = net.get('parameters', {})

        for p in to_list:
            if parameters.get(p):
                parameters[p]['parsed'] = parameters[p]['raw'].split()

        return net

    @private
    async def reg_setparm(self, data):
        return await self.netconf(action='setparm', args=[json.dumps(data)], jsoncmd=True)

    @private
    async def reg_delparm(self, data):
        return await self.netconf(action='delparm', args=[json.dumps(data)], jsoncmd=True)

    @private
    async def reg_getparm(self, share, parm):
        to_list = ['vfs objects', 'hosts allow', 'hosts deny']
        try:
            ret = (await self.netconf(action='getparm', share=share, args=[parm])).strip()
        except CallError as e:
            if f"Error: given parameter '{parm}' is not set." in e.errmsg:
                # Copy behavior of samba python binding
                return None
            else:
                raise

        return ret.split() if parm in to_list else ret

    @private
    async def get_global_params(self, globalconf):
        if globalconf is None:
            globalconf = {}

        gl = {}
        gl.update({
            'fruit_enabled': globalconf.get('fruit_enabled', None),
            'ad_enabled': globalconf.get('ad_enabled', None),
            'nfs_exports': globalconf.get('nfs_exports', None),
            'smb_shares': globalconf.get('smb_shares', None)
        })
        if gl['nfs_exports'] is None:
            gl['nfs_exports'] = await self.middleware.call('sharing.nfs.query', [['enabled', '=', True]])
        if gl['smb_shares'] is None:
            gl['smb_shares'] = await self.middleware.call('sharing.smb.query', [['enabled', '=', True]])
            for share in gl['smb_shares']:
                await self.middleware.call('sharing.smb.strip_comments', share)

        if gl['ad_enabled'] is None:
            gl['ad_enabled'] = (await self.middleware.call('activedirectory.config'))['enable']

        if gl['fruit_enabled'] is None:
            gl['fruit_enabled'] = (await self.middleware.call('smb.config'))['aapl_extensions']

        return gl

    @private
    async def order_vfs_objects(self, vfs_objects):
        vfs_objects_special = ('catia', 'zfs_space', 'fruit', 'streams_xattr', 'shadow_copy_zfs',
                               'noacl', 'ixnas', 'acl_xattr', 'zfsacl', 'nfs4acl_xattr',
                               'glusterfs', 'crossrename', 'recycle', 'zfs_core', 'aio_fbsd', 'io_uring')

        vfs_objects_ordered = []

        if 'fruit' in vfs_objects:
            if 'streams_xattr' not in vfs_objects:
                vfs_objects.append('streams_xattr')

        if 'noacl' in vfs_objects:
            if 'ixnas' in vfs_objects:
                vfs_objects.remove('ixnas')

        for obj in vfs_objects:
            if obj not in vfs_objects_special:
                vfs_objects_ordered.append(obj)

        for obj in vfs_objects_special:
            if obj in vfs_objects:
                vfs_objects_ordered.append(obj)

        return vfs_objects_ordered

    @private
    async def diff_middleware_and_registry(self, share, data):
        if share is None:
            raise CallError('Share name must be specified.')

        if data is None:
            data = await self.middleware.call('sharing.smb.query', [('name', '=', share)], {'get': True})

        await self.middleware.call('sharing.smb.strip_comments', data)
        share_conf = await self.share_to_smbconf(data)
        try:
            reg_conf = (await self.reg_showshare(share if not data['home'] else 'homes'))['parameters']
        except Exception:
            return None

        s_keys = set(share_conf.keys())
        r_keys = set(reg_conf.keys())
        intersect = s_keys.intersection(r_keys)

        return {
            'added': {x: share_conf[x] for x in s_keys - r_keys},
            'removed': {x: reg_conf[x] for x in r_keys - s_keys},
            'modified': {x: share_conf[x] for x in intersect if share_conf[x] != reg_conf[x]},
        }

    @private
    async def apply_conf_registry(self, share, diff):
        set_payload = {"service": share, "parameters": diff["added"] | diff["modified"]}
        del_payload = {"service": share, "parameters": diff["removed"]}

        if set_payload["parameters"]:
            await self.reg_setparm(set_payload)

        if del_payload["parameters"]:
            await self.reg_setparm(del_payload)

    @private
    async def apply_conf_diff(self, target, share, confdiff):
        self.logger.trace('target: [%s], share: [%s], diff: [%s]',
                          target, share, confdiff)
        if target not in ['REGISTRY', 'FNCONF']:
            raise CallError(f'Invalid target: [{target}]', errno.EINVAL)

        if target == 'FNCONF':
            # TODO: add ability to convert the registry back to our sqlite table
            raise CallError('FNCONF target not implemented')

        return await self.apply_conf_registry(share, confdiff)

    @private
    async def add_multiprotocol_conf(self, conf, gl, data):
        nfs_path_list = []
        for export in gl['nfs_exports']:
            nfs_path_list.extend(export['paths'])

        if any(filter(lambda x: f"{conf['path']}/" in f"{x}/", nfs_path_list)):
            self.logger.debug("SMB share [%s] is also an NFS export. "
                              "Applying parameters for mixed-protocol share.", data['name'])
            conf.update({
                "strict locing": {"parsed": True},
                "posix locking": {"parsed": True},
                "level2 oplocks": {"parsed": False},
                "oplocks": {"parsed": False},
            })
            if data['durablehandle']:
                self.logger.warn("Disabling durable handle support on SMB share [%s] "
                                 "due to NFS export of same path.", data['name'])
                await self.middleware.call('datastore.update', 'sharing.cifs_share',
                                           data['id'], {'cifs_durablehandle': False})
                data['durablehandle'] = {"parsed": False}

    @private
    @filterable
    async def registry_query(self, filters, options):
        """
        Filterable method for querying SMB shares from the registry
        config. Can be reverted back to registry / smb.conf without
        loss of information. This is necessary to provide consistent
        API for viewing samba's current running configuration, which
        is of particular importance with clustered registry shares.
        """
        try:
            reg_shares = await self.reg_list()
        except CallError:
            return []

        rv = []
        for idx, s in enumerate(reg_shares['sections']):
            if not s['is_share']:
                continue

            is_home = s['service'] == "HOMES"
            s["parameters"]["name"] = "HOMES_SHARE" if is_home else s['service']
            s["parameters"]["home"] = is_home
            parsed_conf = await self.smbconf_to_share(s['parameters'])

            entry = {"id": idx + 1}
            entry.update(parsed_conf)
            rv.append(entry)

        return filter_list(rv, filters, options)

    @private
    async def smbconf_convert(self, conf, ret, key, entry):
        val = conf.pop(entry['smbconf'], entry['default'])
        if type(val) != dict:
            ret[key] = entry['default']
            return

        if type(entry['default']) == list:
            ret[key] = val['parsed'].split()
            return

        ret[key] = val['parsed']

    @private
    async def smbconf_to_share(self, data):
        """
        Wrapper to convert registry share into approximation of
        normal API return for sharing.smb.query.
        Disabled and locked shares are not in samba's running
        configuration in registry.tdb and so we assume that this
        is not the case.
        """
        ret = {}
        conf_in = data.copy()
        vfs_objects = conf_in.pop("vfs objects", "")
        hostsallow = conf_in.pop("hosts allow", None),
        hostsdeny = conf_in.pop("hosts deny", None),
        """
        ret = {
            "purpose": "NO_PRESET",
            "path": conf_in.pop("path")['raw'],
            "path_suffix": "",
            "home": conf_in.pop("home", False)['raw'],
            "name": conf_in.pop("name")['raw'],
            "guestok": conf_in.pop("guest ok")['parsed'],
            "browsable": conf_in.pop("browseable")['parsed'],
            "hostsallow": hostsallow['raw'].split() if hostsallow else [],
            "hostsdeny": hostsdeny['raw'].split() if hostsdeny else [],
            "abe": conf_in.pop("access based share enumeration", False),
            "acl": True if "acl_xattr" in vfs_objects else False,
            "ro": conf_in.pop("read only", "yes") == "yes",
            "durable handle": conf_in.pop("posix locking", "yes") == "no",
            "streams": True if "streams_xattr" in vfs_objects else False,
            "timemachine": conf_in.pop("fruit:time machine", False),
            "recyclebin": True if "recycle" in vfs_objects else False,
            "cluster_volname": conf_in.pop("glusterfs: volume", ""),
            "fsrvp": False,
            "enabled": True,
            "locked": False,
            "shadowcopy": False,
            "aapl_name_mangling": True if "catia" in vfs_objects else False,
        }
        """
        for k, v in DEFAULT_SHARE_PARAMETERS.items():
            await self.smbconf_convert(conf_in, ret, k, v)

        ret = {
            "purpose": "NO_PRESET",
            "streams": True if "streams_xattr" in vfs_objects else False,
            "timemachine": conf_in.pop("fruit:time machine", False),
            "recyclebin": True if "recycle" in vfs_objects else False,
            "home": conf_in.pop("home", False),
            "name": conf_in.pop("name"),
            "fsrvp": False,
            "enabled": True,
            "locked": False,
            "shadowcopy": False,
            "aapl_name_mangling": True if "catia" in vfs_objects else False,
        }
        cluster_logfile = conf_in.pop("glusterfs: logfile", "")
        aux_list = [f"{k} = {v['raw']}" for k, v in conf_in.items()]
        ret["auxsmbconf"] = '\n'.join(aux_list)
        return ret

    @private
    async def normalize_config(self, conf):
        for v in conf.values():
            if type(v.get('parsed')) == list:
                v['raw'] = ' '.join(v['parsed'])
            elif not v.get('raw'):
                v['raw'] = str(v['parsed'])

    @private
    async def share_to_smbconf(self, conf_in, globalconf=None):
        data = conf_in.copy()
        gl = await self.get_global_params(globalconf)
        await self.middleware.call('sharing.smb.strip_comments', data)
        conf = {}
        is_clustered = bool(data.get("cluster_volname", ""))

        if data['home'] and gl['ad_enabled']:
            data['path_suffix'] = '%D/%U'
        elif data['home'] and data['path']:
            data['path_suffix'] = '%U'

        if data['path']:
            try:
                ds = await self.middleware.call('pool.dataset.from_path', data['path'], False)
                acltype = ds['acltype']['value']
            except Exception:
                self.logger.warning("Failed to obtain ZFS dataset for path %s. "
                                    "Unable to automatically configuration ACL settings.",
                                    data['path'], exc_info=True)
                acltype = "UNKNOWN"
            path = '/'.join([data['path'], data['path_suffix']]) if data['path_suffix'] else data['path']
            conf['path'] = {"parsed": path}
        else:
            """
            An empty path may be valid for a [homes] share.
            In this situation, samba will generate the share path during TCON
            using user's home directory. This makes it impossible for us to
            determine correct configuration for share, but some customers rely
            on this particular old samba feature.
            """
            acltype = "UNKNOWN"
            conf['path'] = {"parsed": ""}

        if is_clustered:
            conf["glusterfs: volume"] = {"parsed": data["cluster_volname"]}
            conf["glusterfs: logfile"] = {"parsed": f'/var/log/samba4/glusterfs-{data["cluster_volname"]}.log'}
            data['vfsobjects'] = ['glusterfs', 'io_uring']
        else:
            data['vfsobjects'] = ['zfs_core', 'io_uring']

        if data['comment']:
            conf["comment"] = {"parsed": data['comment']}
        if not data['browsable']:
            conf["browseable"] = {"parsed": False}
        if data['abe']:
            conf["access based share enum"] = {"parsed": True}
        if data['hostsallow']:
            conf["hosts allow"] = {"parsed": data['hostsallow']}
        if data['hostsdeny']:
            conf["hosts deny"] = {"parsed": data['hostsdeny']}
        conf["read only"] = {"parsed": data["ro"]}
        conf["guest ok"] = {"parsed": data["guestok"]}

        if gl['fruit_enabled']:
            data['vfsobjects'].append('fruit')

        if data['acl']:
            if acltype == "NFSV4":
                data['vfsobjects'].append('nfs4acl_xattr')
                conf.update({
                    "nfs4acl_xattr:nfs4_id_numeric": {"parsed": True},
                    "nfs4acl_xattr:validate_mode": {"parsed": True},
                    "nfs4acl_xattr:xattr_name": {"parsed": "system.nfs4_acl_xdr"},
                    "nfs4acl_xattr:encoding": {"parsed": "xdr"},
                })
            elif acltype == "POSIX" or acltype == "UNKNOWN":
                data['vfsobjects'].append('acl_xattr')
            else:
                self.logger.debug("ACLs are disabled on path %s. "
                                  "Disabling NT ACL support.",
                                  data['path'])
                conf["nt acl support"] = {"parsed": False}
        else:
            conf["nt acl support"] = {"parsed": False}

        if data['recyclebin']:
            # crossrename is required for 'recycle' to work across sub-datasets
            # FIXME: crossrename imposes 20MB limit on filesize moves across mountpoints
            # This really needs to be addressed with a zfs-aware recycle bin.
            data['vfsobjects'].extend(['recycle', 'crossrename'])

        if data['shadowcopy'] or data['fsrvp']:
            data['vfsobjects'].append('shadow_copy_zfs')

        if data['durablehandle']:
            conf.update({
                "kernel oplocks": {"parsed": False},
                "kernel share modes": {"parsed": False},
                "posix locking": {"parsed": False},
            })

        if data['fsrvp']:
            data['vfsobjects'].append('zfs_fsrvp')
            conf.update({
                "shadow:ignore_empty_snaps": {"parsed": False},
                "shadow:include": {"parsed", "fss-*"},
            })

        conf.update({
            "nfs4:chown": {"parsed": True},
            "ea support": {"parsed": False},
        })

        if data['aapl_name_mangling']:
            data['vfsobjects'].append('catia')
            if gl['fruit_enabled']:
                conf.update({
                    'fruit:encoding': {"parsed": 'native'},
                    'mangled names': {"parsed": False},
                })
            else:
                conf.update({
                    'catia:mappings': {"parsed": ','.join(FRUIT_CATIA_MAPS)},
                    'mangled names': {"parsed": False},
                })

        if data['purpose'] == 'ENHANCED_TIMEMACHINE':
            data['vfsobjects'].append('tmprotect')
        elif data['purpose'] == 'WORM_DROPBOX':
            data['vfsobjects'].append('worm')

        if data['streams']:
            data['vfsobjects'].append('streams_xattr')
            conf['smbd:max_xattr_size'] = {"parsed": 2097152}

        conf["vfs objects"] = {"parsed": await self.order_vfs_objects(data['vfsobjects'])}

        if gl['fruit_enabled']:
            conf["fruit:metadata"] = {"parsed": "stream"}
            conf["fruit:resource"] = {"parsed": "stream"}

        if conf["path"]:
            await self.add_multiprotocol_conf(conf, gl, data)

        if data['timemachine']:
            conf["fruit:time machine"] = {"parsed": True}
            conf["fruit:locking"] = {"parsed": "none"}

            if data['timemachine_quota']:
                conf['fruit:time machine max size'] = {"parsed": f'{data["timemachine_quota"]}G'}

        if data['afp']:
            conf['fruit:encoding'] = {"parsed": 'native'}
            conf['fruit:metadata'] = {"parsed": 'netatalk'}
            conf['fruit:resource'] = {"parsed": 'file'}
            conf['streams_xattr:prefix'] = {"parsed": 'user.'}
            conf['streams_xattr:store_stream_type'] = {"parsed": False}
            conf['streams_xattr:xattr_compat'] = {"parsed": True}

        if data['recyclebin']:
            conf.update({
                "recycle:repository": {"parsed": ".recycle/%D/%U" if gl['ad_enabled'] else ".recycle/%U"},
                "recycle:keeptree": {"parsed": True},
                "recycle:versions": {"parsed": True},
                "recycle:touch": {"parsed": True},
                "recycle:directory_mode": {"parsed": "0777"},
                "recycle:subdir_mode": {"parsed": "0700"},
            })

        if not data['auxsmbconf']:
            data['auxsmbconf'] = (SMBSharePreset[data["purpose"]].value)["params"]["auxsmbconf"]

        for param in data['auxsmbconf'].splitlines():
            if not param.strip():
                continue
            try:
                auxparam, val = param.split('=', 1)
                """
                vfs_fruit must be added to all shares if fruit is enabled.
                Support for SMB2 AAPL extensions is determined on first tcon
                to server, and so if they aren't appended to any vfs objects
                overrides via auxiliary parameters, then users may experience
                unexpected behavior.
                """
                if auxparam.strip() == "vfs objects" and gl['fruit_enabled']:
                    vfsobjects = val.strip().split()
                    vfsobjects.append('fruit')
                    conf['vfs objects'] = {"parsed": await self.order_vfs_objects(vfsobjects)}
                else:
                    conf[auxparam.strip()] = {"raw": val.strip()}
            except Exception:
                self.logger.debug("[%s] contains invalid auxiliary parameter: [%s]",
                                  data['name'], param)

        await self.normalize_config(conf)

        return conf
