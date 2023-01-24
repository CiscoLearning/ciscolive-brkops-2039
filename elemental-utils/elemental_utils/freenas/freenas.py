import os
import time
import requests
from urllib3.exceptions import InsecureRequestWarning
from .query import Request
from typing import List, Dict

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

TIMEOUT = 60


class ElementalFreeNas(object):
    def __init__(self, ip: str, username: str = None, password: str = None):
        """
        Class to interact with FreeNAS servers in a limited way as needed by Elemental.

        :param ip: IP address of FreeNAS server
        :param username: Username of administrative FreeNAS user
        :param password: Password of administrative FreeNAS user
        """

        try:
            if not username:
                self.username = os.environ["FREENAS_USERNAME"]
            else:
                self.username = username

            if not password:
                self.password = os.environ["FREENAS_PASSWORD"]
            else:
                self.password = password
        except KeyError as e:
            raise KeyError(f"Parameter {e} must either be set in the environment or passed to the constructor")

        self.base_url = f"https://{ip}/api/v2.0/"

        self.http_session = requests.Session()

    def _get_req(self, uri: str) -> Request:
        return Request(base=self.base_url + uri, http_session=self.http_session, authorization=(self.username, self.password))

    def integrate_with_ad(self, domain: str, netbios_name: str, join_account: str, join_password: str) -> None:
        """
        Integrate a FreeNAS server with an Active Directory domain

        :param domain: Active Directory domain name with which to integrate
        :param netbios_name: NetBIOS name of the host to add to AD (must be 16 characters or less)
        :param join_account: Username of the account to use to integrate with AD
        :param join_password: Password of join account
        """

        req = self._get_req(uri="activedirectory")

        payload = {
            "domainname": domain,
            "bindname": join_account,
            "bindpw": join_password,
            "netbiosname": netbios_name,
            "enable": True,
        }

        req.put(payload)

        req = self._get_req(uri="activedirectory/get_state")

        i = 0
        while i < TIMEOUT:
            state = req.get()
            if state and state[0] == "HEALTHY":
                break

            time.sleep(1)
            i += 1

        if i >= TIMEOUT:
            raise Exception(f"Timeout joining domain {domain} after {TIMEOUT} seconds")

    def get_pools(self) -> List[Dict]:
        """
        Get a list of pools from a FreeNAS server.

        :return list of pool details
        """

        req = self._get_req(uri="pool")

        return req.get()

    def get_pool(self, pool: str) -> dict:
        """
        Get details of a single pool.

        :return pool details
        """

        req = self._get_req(uri="pool")
        pool_obj = req.get(add_params={"name": pool})

        if pool_obj:
            return pool_obj[0]

        return None

    def add_pool(self, name: str, disks: List[str]) -> None:
        """
        Create a ZFS pool on a FreeNAS server.

        :return True if the pool was successfully created, False otherwise
        """

        req = self._get_req(uri="pool")

        payload = {"name": name, "topology": {"data": [{"type": "STRIPE", "disks": disks}]}}

        req.post(payload)

        i = 0
        while i < TIMEOUT:
            pool = self.get_pool(pool=name)
            if pool and pool["status"] == "ONLINE":
                break

            time.sleep(1)
            i += 1

        if i >= TIMEOUT:
            raise Exception(f"Timeout waiting for pool {name} to be online")

    def add_disk(self, pool: str, disks: List[str]) -> None:
        """
        Add a disk or disks to a ZFS pool, and then expand to take all space.

        :param pool: Name of pool to which to add disks
        :param disks: List of disks to add to pool
        """

        req = self._get_req(uri=f"pool/id/{pool}")

        pool_obj = req.get()

        if not pool_obj:
            raise Exception(f"Failed to find pool {pool}")

        for raid in pool_obj[0]["topology"]["data"]:
            if raid["type"] == "STRIPE":
                raid["disks"].expand(disks)
                break

        req.put(pool_obj[0])

        req = self._get_req(uri=f"pool/id/{pool}/expand")
        req.post({})

    def add_dataset(self, pool: str, name: str) -> None:
        """
        Add a dataset to a pool.

        :param pool: Name of pool on which to create a dataset
        :param name: Name of the dataset to add
        """

        req = self._get_req(uri="pool/dataset")

        payload = {"name": f"{pool}/{name}", "type": "FILESYSTEM"}

        req.post(payload)

    def add_nfs_share(self, path: str, networks: List[str]) -> None:
        """
        Add a new NFS share.

        :param path: Path to the dataset to share
        :param networks: List of networks to allow access to the share
        """

        req = self._get_req(uri="sharing/nfs")

        payload = {"paths": [path], "alldirs": True, "networks": networks, "maproot_user": "root"}

        req.post(payload)

    def add_smb_share(self, path: str, name: str, networks: List[str]) -> None:
        """
        Add a new SMB share.

        :param path: Path to the dataset to share
        :param name: Name of the share to export
        :param networks: List of networks to allow access to the share
        """

        req = self._get_req(uri="sharing/smb")

        payload = {
            "path": path,
            "home": False,
            "name": name,
            "hostsallow": networks,
            "guestok": False,
        }

        req.post(payload)

    def set_share_perms(self, path: str, group: str) -> None:
        """
        Defines share-level permissions (allows a group read-write access).

        :param path: Path to filesystem on which to set permissions
        :param group: Name of the group to allow access
        """

        req = self._get_req(uri="group/get_group_obj")
        payload = {"groupname": group}

        try:
            group_obj = req.post(payload)
        except Exception as e:
            raise Exception(f"Unable to find group {group}: {e}")

        gid = group_obj[0]["gr_gid"]

        req = self._get_req(uri="filesystem/setacl")

        payload = {
            "path": path,
            "uid": 0,
            "gid": gid,
            "dacl": [
                {
                    "tag": "owner@",
                    "id": None,
                    "type": "ALLOW",
                    "perms": {
                        "BASIC": "FULL_CONTROL",
                    },
                    "flags": {
                        "BASIC": "INHERIT",
                    },
                },
                {"tag": "group@", "id": None, "type": "ALLOW", "perms": {"BASIC": "MODIFY"}, "flags": {"BASIC": "INHERIT"}},
                {"tag": "everyone@", "id": None, "type": "ALLOW", "perms": {"BASIC": "MODIFY"}, "flags": {"BASIC": "INHERIT"}},
            ],
            "acltype": "NFS4",
        }

        req.post(payload)

    def set_smb_permissions(self, share_name: str, domain: str, group: str) -> None:
        """
        Set the SMB-level permissions on a share

        :param share_name: Name of the share
        :param domain: Active Directory domain name
        :param group: AD group
        """

        req = self._get_req(uri="smb/sharesec")
        payload = {
            "share_name": share_name,
            "share_acl": [
                {
                    "ae_type": "ALLOWED",
                    "ae_perm": "FULL",
                    "ae_who_name": {
                        "domain": domain,
                        "name": group,
                    },
                }
            ],
        }

        req.post(payload)

    def enable_nfs(self) -> None:
        """
        Enable the NFS service
        """

        req = self._get_req(uri="service/start")
        req.post({"service": "nfs"})

        req = self._get_req(uri="service/id/nfs")
        req.put({"enable": True})

    def configure_nfs(self) -> None:
        """
        Configure NFS service using Elemental defaults.
        """

        req = self._get_req(uri="nfs")

        payload = {
            "v4": True,
            "v4_v3owner": True,
        }

        req.put(payload)

    def enable_snmp(self) -> None:
        """
        Enable the SNMP service
        """

        req = self._get_req(uri="service/start")
        req.post({"service": "snmp"})

        req = self._get_req(uri="service/snmp/id")
        req.put({"enable": True})

    def configure_snmp(self, location: str, username: str, password: str, contact: str = "") -> None:
        """
        Configure SNMPv3 using Elemental defaults.
        """

        req = self._get_req(uri="snmp")

        payload = {
            "location": location,
            "contact": contact,
            "v3": True,
            "v3_username": username,
            "v3_authtype": "SHA",
            "v3_password": password,
            "v3_privproto": "AES",
            "v3_privpassphrase": password,
        }

        req.put(payload)

    def disable_console_menu(self) -> None:
        """
        Disable the FreeNAS console menu (leaving it enabled is a security risk)
        """

        req = self._get_req(uri="system/advanced")
        req.put({"consolemenu": False})

    def change_root_password(self, root_password: str) -> None:
        """
        Change root's password.

        :param root_password: New password for user root
        """

        req = self._get_req(uri="user")
        root = req.get(add_params={"username": "root"})

        req = self._get_req(uri=f"user/id/{root[0]['id']}")
        req.put({"password": root_password})

    def set_syslog_server(self, syslog_server: str) -> None:
        """
        Set the syslog server to the given IP address.

        :param syslog_server: IP address of syslog server
        """

        req = self._get_req(uri="system/advanced")
        req.put({"syslogserver": syslog_server, "sysloglevel": "F_INFO", "syslogtransport": "UDP"})
