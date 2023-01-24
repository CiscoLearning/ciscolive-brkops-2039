import hvac
import os


class ElementalVault(object):
    def __init__(self, mount_point: str = "elemental", vault_address: str = None, vault_username: str = None, vault_password: str = None, vault_token: str = None):
        """
        Class for wrapping Vault's hvac to provide Elemental convenience.

        :param mount_point: Vault mount point to use (default "cisco")
        :param vault_address: Optional URL for Vault (if omitted, it is taken from the environment)
        :param vault_username: Optional Vault LDAP username (it omitted, it is taken from the environment)
        :param vault_password: Optional Vault LDAP password (it omitted, it is taken from the environment)
        :param vault_token: Optional Vault token (default is to use token, if given, 
                            either as an environment variable or argument)

        Must specify either a token or a username and password for credentials.  
        Priority for authentication is as follows:
            1) if vault_token exists it is used
            2) if VAULT_TOKEN environment var exists, it is used
            3) if vault_username and vault_password exist, they are used
            4) if VAULT_USERNAME and VAULT_PASSWORD env vars exist, they are used
            5) if none of the above are true an error is thrown
        Object will not be instantiated if neither vault_address or env(VAULT_ADDRESS) exists.
        """

        if not vault_address:
            vault_address = os.environ.get("VAULT_ADDRESS")

        #default is to use vault_token, if given
        if not vault_token:
            vault_token= os.environ.get("VAULT_TOKEN")
        
        if vault_token and vault_address:
            self._vault_client = hvac.Client(url=vault_address)
            self._vault_client.token = vault_token
        else:
            if not vault_username:
                vault_username = os.environ.get("VAULT_USERNAME")

            if not vault_password:
                vault_password = os.environ.get("VAULT_PASSWORD")


            if not all([vault_address, vault_username, vault_password]):
                raise Exception(
                    "Missing Vault address and/or credentials.  Either pass them to the constructor, or set environment variables."
                    "Address is VAULT_ADDRESS. Credentials can be either VAULT_TOKEN or VAULT_USERNAME w/ VAULT_PASSWORD."
                )
            self._vault_client = hvac.Client(url=vault_address)
            self._vault_client.auth.ldap.login(username=vault_username, password=vault_password)
    
        if not self._vault_client.is_authenticated():
            raise Exception("Failed to authenticate to Vault")

        self._mount_point = mount_point

    def lookup(self, path: str, keys: list) -> dict:
        """Given a path, lookup the key or keys at that path.

        :param path: Path to look for keys
        :param keys: List of keys to extract from secret
        :return dict Mapping of key to secret value
        """
        result = {}
        secrets = self._vault_client.secrets.kv.v2.read_secret(path=path, mount_point=self._mount_point)
        if "data" in secrets and "data" in secrets["data"]:
            for key in keys:
                if key in secrets["data"]["data"]:
                    result[key] = secrets["data"]["data"][key]
                else:
                    result[key] = None
        else:
            raise ValueError(f"Secret not found in Vault, {path}")

        return result
        