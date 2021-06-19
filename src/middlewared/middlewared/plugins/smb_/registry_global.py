from middlewared.service import private, Service
from middlewared.service_exception import CallError
from middlewared.utils import run
from middlewared.plugins.smb import SMBCmd, LOGLEVEL_MAP
from middlewared.plugins.activedirectory import DEFAULT_AD_PARAMETERS
from middlewared.plugins.ldap import DEFAULT_LDAP_PARAMETERS
from middlewared.utils import osc

import errno

DEFAULT_GLOBAL_PARAMETERS = {
    "dns proxy": {"smbconf": "dns proxy", "default": False},
    "max log size": {"smbconf": "max log size", "default": 51200},
    "load printers": {"smbconf": "load printers", "default": False},
    "printing": {"smbconf": "printing", "default": "bsd"},
    "printcap": {"smbconf": "printcap", "default": "/dev/null"},
    "disable spoolss": {"smbconf": "disable spoolss", "default": True},
    "dos filemode": {"smbconf": "dos filemode", "default": True},
    "kernel change notify": {"smbconf": "kernel change notify", "default": True},
    "enable web service discovery": {"smbconf": "enable web service discovery", "default": True},
    "bind interfaces only": {"smbconf": "bind interfaces only", "default": True},
    "registry": {"smbconf": "registry", "default": True},
    "registry shares": {"smbconf": "registry shares", "default": True},
}

GLOBAL_SCHEMA = {
    "netbiosname": {"smbconf": "tn:netbiosname", "default": "truenas"},
    "netbiosname_b": {"smbconf": "tn:netbiosname_b", "default": "truenase-b"},
    "netbiosname_local": {"smbconf": "netbios name", "default": ""},
    "workgroup": {"smbconf": "workgroup", "default": "WORKGROUP"},
    "cifs_SID": {"smbconf": "tn:sid", "default": ""},
    "netbiosalias": {"smbconf": "netbios aliases", "default": []},
    "description": {"smbconf": "server string", "default": ""},
    "enable_smb1": {"smbconf": "server min protocol", "default": "SMB2_10"},
    "unixcharset": {"smbconf": "unix charset", "default": "UTF8"},
    "syslog": {"smbconf": "syslog only", "default": False},
    "apple_extensions": {"smbconf": "tn:fruit_enabled", "default": False},
    "localmaster": {"smbconf": None, "default": False},
    "loglevel": {"smbconf": None, "default": 1},
    "guest": {"smbconf": "guest account", "default": "nobody"},
    "admin_group": {"smbconf": "tn:admin_group", "default": ""},
    "filemask": {"smbconf": "create mask", "default": "0775"},
    "dirmask": {"smbconf": "directory mask", "default": "0775"},
    "ntlmv1_auth": {"smbconf": "ntlm auth", "default": False},
    "bindip": {"smbconf": None, "default": ""},
}


class SMBService(Service):

    class Config:
        service = 'cifs'
        service_verb = 'restart'

    @private
    async def reg_default_params(self):
        ret = {}
        ret['smb'] = DEFAULT_GLOBAL_PARAMETERS.keys()
        ret['ad'] = DEFAULT_AD_PARAMETERS.keys()
        ret['ldap'] = DEFAULT_LDAP_PARAMETERS.keys()
        return ret

    @private
    async def strip_idmap(self, reg_defaults):
        """
        All params related to idmap backends will be handled
        in idmap plugin.
        """
        idmap_params = {}
        for k, v in reg_defaults.items():
            if k.startswith("idmap config"):
                idmap_params[k] = v

        for e in idmap_params.keys():
            reg_defaults.pop(e, "")

        return idmap_params

    @private
    async def strip_directory_services(self, reg_defaults):
        def_ds_params = []
        def_ds_params.extend(DEFAULT_AD_PARAMETERS.keys())
        def_ds_params.extend(DEFAULT_LDAP_PARAMETERS.keys())
        ds_params = {}

        for k, v in reg_defaults.items():
            if k in def_ds_params:
                ds_params[k] = v

        for e in ds_params.keys():
            reg_defaults.pop(e, "")

        return ds_params

    @private
    async def reg_globals(self):
        """
        Split smb.conf parameters into portions used by relevant plugins.

        `raw` contains unmodified smb.conf
        `idmap` contains idmap configuration
        `ds` contains directory service configuration
        `smb` contains smb service configuation (smb plugin)
        """
        ret = {}
        """
        reg_showshare will fail for `global` if registry has no global entries.
        In this case simply return an empty config (since it's actually empty anyway).
        """
        try:
            global_conf = await self.middleware.call('sharing.smb.reg_showshare', 'global')
        except CallError as e:
            if e.errno == errno.ENXIO:
                self.logger.warning("Unable to query globals due to unhealthy ctdb state")
            return {'raw': {}, 'idmap': {}, 'ds': {}, 'smb': {}}
        except Exception:
            self.logger.debug("Failed to retrieve global share config from registry")
            return {'raw': {}, 'idmap': {}, 'ds': {}, 'smb': {}}

        ret['raw'] = global_conf['parameters'].copy()
        ret['idmap'] = await self.strip_idmap(global_conf['parameters'])
        ret['ds'] = await self.strip_directory_services(global_conf['parameters'])
        ret['smb'] = global_conf['parameters']
        return ret

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
    async def reg_config(self):
        """
        This co-routine is called in smb.config() when cluster support is enabled.
        In a clustered configuration, we rely exclusively on the contents of the
        clustered SMB configuration in Samba's registry.
        """
        ret = {"id": 1}
        reg_globals = (await self.middleware.call('smb.reg_globals'))['smb']
        bind_ips = reg_globals.pop("interfaces", {"raw": ""})
        bind_ips = bind_ips['raw'].split()
        if bind_ips:
            bind_ips.remove("127.0.0.1")

        reg_globals.pop("bind interfaces only", "")
        loglevel = reg_globals.pop("log level", {"raw": "1"})
        if loglevel['raw'].startswith("syslog@"):
            loglevel['raw'] = loglevel[len("syslog@")]

        llevel = LOGLEVEL_MAP.get(loglevel['raw'].split()[0])

        for k, v in GLOBAL_SCHEMA.items():
            await self.smbconf_convert(reg_globals, ret, k, v)

        ret.update({
            "bindip": bind_ips,
            "loglevel": llevel,
            "localmaster": False,
        })

        ret["enable_smb1"] = (ret["enable_smb1"] == "NT1")

        reg_globals.pop('logging', "file")
        aux_list = [f"{k} = {v}" for k, v in reg_globals.items()]
        ret['smb_options'] = '\n'.join(aux_list)
        return ret

    @private
    async def global_setparm(self, data):
        cmd = await run([SMBCmd.NET.value, '--json', 'conf', 'setparm', json.dumps(data)], check=False)
        if cmd.returncode != 0:
            raise CallError(f"Failed to set parameter [{parameter}] to [{value}]: "
                            f"{cmd.stderr.decode().strip()}")

    @private
    async def global_delparm(self, data):
        cmd = await run([SMBCmd.NET.value, '--json', 'conf', 'delparm', json.dumps(data)], check=False)
        if cmd.returncode != 0:
            raise CallError(f"Failed to delete parameter [{parameter}]: "
                            f"{cmd.stderr.decode().strip()}")

    @private
    async def reg_apply_conf_diff(self, diff):
        to_add = diff.get('added', {})
        to_delete = diff.get('removed', {})
        to_modify = diff.get('modified', {})
        for k, v in to_add.items():
            await self.global_setparm(k, v)

        for k, v in to_modify.items():
            await self.global_setparm(k, v[0])

        for k in to_delete.keys():
            await self.global_delparm(k)

    @private
    async def reg_update(self, data):
        diff = await self.diff_conf_and_registry(data, True)
        self.logger.debug("DIFF: %s", diff)
        await self.reg_apply_conf_diff(diff)

    @private
    async def get_smb_homedir(self, gen_params):
        homedir = "/home"
        if "HOMES" in gen_params['shares']:
            homedir = (await self.middleware.call("sharing.smb.reg_showshare", "HOMES"))['path']
        return homedir

    @private
    async def pam_is_required(self, gen_params):
        """
        obey pam restictions parameter is requried to allow pam_mkhomedir to operate on share connect.
        It is also required to enable kerberos auth in LDAP environments
        """
        if "HOMES" in gen_params['shares']:
            return True
        if gen_params['role'] == 'ldap_member':
            return True

        return False

    @private
    async def add_bind_interfaces(self, smbconf, ips_to_check):
        """
        smbpasswd by default connects to 127.0.0.1 as an SMB client. For this reason, localhost is added
        to the list of bind ip addresses here.
        """
        allowed_ips = await self.middleware.call('smb.bindip_choices')
        validated_bind_ips = []
        for address in ips_to_check:
            if allowed_ips.get(address):
                validated_bind_ips.append(address)
            else:
                self.logger.warning("IP address [%s] is no longer in use "
                                    "and should be removed from SMB configuration.",
                                    address)

        if validated_bind_ips:
            bindips = validated_bind_ips
            bindips.insert(0, "127.0.0.1")
            smbconf['interfaces'] = " ".join(bindips)

        smbconf['bind interfaces only'] = 'Yes'

    @private
    async def get_ds_role(self, params):
        params['ad'] = await self.middleware.call("activedirectory.config")
        params['ldap'] = await self.middleware.call("ldap.config")
        if params['ad']['enable']:
            params['role'] = 'ad_member'
        elif params['ldap']['enable'] and params['ldap']['has_samba_schema']:
            params['role'] = 'ldap_member'

    @private
    async def diff_conf_and_registry(self, data, full_check):
        """
        return differences between running configuration and a dict of smb.conf parameters.
        When full_check is True, then we diff the full running configuration.
        """
        new_conf = await self.global_to_smbconf(data)
        running_conf = (await self.middleware.call('smb.reg_globals'))['smb']

        s_keys = set(new_conf.keys())
        r_keys = set(running_conf.keys())
        intersect = s_keys.intersection(r_keys)
        return {
            'added': {x: new_conf[x] for x in s_keys - r_keys},
            'removed': {x: running_conf[x] for x in r_keys - s_keys} if full_check else {},
            'modified': {x: new_conf[x]for x in intersect if new_conf[x] != running_conf[x]},
        }

    @private
    async def global_to_smbconf(self, data):
        """
        Convert the SMB share config into smb.conf parameters prior to
        registry insertion. Optimization in this case to _only_ set bare minimum
        parameters to reflect the specified smb service configuration.
        """
        loglevelint = LOGLEVEL_MAP.inv.get(data['loglevel'], "MINIMUM")
        loglevel = f"{loglevelint} auth_json_audit:3@/var/log/samba4/auth_audit.log"
        if data['syslog']:
            logging = f'syslog@{"3" if loglevelint > 3 else data["loglevel"]} file'
        else:
            logging = "file"

        to_set = {
            "server string": data["description"],
            "tn:netbiosname": data["netbiosname"],
            "tn:netbiosname_b": data["netbiosname_b"],
            "netbiosname": data["netbiosname_local"],
            "workgroup": data["workgroup"],
            "tn:sid": data["cifs_SID"],
            "netbios aliases": " ".join(data["netbiosalias"]),
            "server min protocol": "NT1" if data['enable_smb1'] else "SMB2_02",
            "unixcharset": data["unixcharset"],
            "syslog only": "Yes" if data["syslog"] else "No",
            "tn:fruit_enabled": "Yes" if data["aapl_extensions"] else "No",
            "local master": "Yes" if data["localmaster"] else "No",
            "guest account": data["guest"],
            "tn:admin_group": data["admin_group"] if data["admin_group"] else "",
            "create mask": data["filemask"] if data["filemask"] else "0775",
            "directory mask": data["dirmask"] if data["dirmask"] else "0775",
            "ntlm auth": "Yes" if data["ntlmv1_auth"] else "No",
            "log level": loglevel,
            "logging": logging,
        }

        for i in data.get('smb_options', '').splitlines():
            kv = i.split("=", 1)
            if len(kv) != 2:
                continue
            to_set.update({kv[0]: kv[1]})

        await self.add_bind_interfaces(to_set, data.get('bindip', []))
        return to_set

    @private
    async def initialize_globals(self):
        data = await self.middleware.call('smb.config')
        await self.reg_update(data)
