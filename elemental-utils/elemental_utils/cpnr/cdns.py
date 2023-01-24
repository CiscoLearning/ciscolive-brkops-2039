import os
from .models import exception
from .query import Request
from ..vault import ElementalVault
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry  # pyright: reportMissingImports=false
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class ElementalCdns(object):
    def __init__(self, url, username: str = None, password: str = None, site: str = None):
        if not username:
            self.username = os.environ.get("CPNR_USERNAME")
        else:
            self.username = username

        if not password:
            self.password = os.environ.get("CPNR_PASSWORD")
        else:
            self.password = password

        if not self.username and site:
            self.username = "service_cpnr"

            ev = ElementalVault()
            keys = ev.lookup(path=f"{site.lower()}/z0/security/{site.lower()}-z0-vm-ad-01/service-accounts/service_cpnr", keys=["password"])
            self.password = keys["password"]

        if not self.username or not self.password:
            raise Exception(
                "CPNR credentials not provided.  Either pass them to the constructor, use CPNR_USERNAME/CPNR_PASSWORD in the environment or"
                " use Vault."
            )

        self.base_url = f"{url if url[-1] != '/' else url[:-1]}/"

        retry_strategy = Retry(backoff_factor=1, total=3)
        adapter = HTTPAdapter(max_retries=retry_strategy)

        self.http_session = requests.Session()
        self.http_session.mount("https://", adapter)

        self.exception = exception.Exception(self)

        self.reload_server = Request(
            base=self.base_url + "web-services/rest/resource/DNSCachingServer",
            filters={"action": "reloadServer"},
            authorization=(self.username, self.password),
            http_session=self.http_session,
        ).action

    def __eq__(self, other):
        if isinstance(other, ElementalCdns):
            return self.base_url == other.base_url

        return False

    def __ne__(self, other):
        if isinstance(other, ElementalCdns):
            return self.base_url != other.base_url

        return True

    def __hash__(self):
        return hash(repr(self))
