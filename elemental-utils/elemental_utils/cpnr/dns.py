import os
import dns.resolver
from .models import host, zone, rzone, rrset
from .query import Request
from ..vault import ElementalVault
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry  # pyright: reportMissingImports=false
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class ElementalDns(object):
    def __init__(self, url: str = None, domain: str = None, username: str = None, password: str = None, site: str = None):
        if not domain and not url:
            raise ValueError("Either one of 'url' or 'domain' must be specified.")

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

        if url:
            self.base_url = f"{url if url[-1] != '/' else url[:-1]}/"
        else:
            try:
                soa_answer = dns.resolver.resolve(domain, "SOA")
                self.base_url = f"{soa_answer[0].mname}:8443/"
            except Exception as e:
                raise ValueError(f"Failed to find a DNS server for {domain}: {e}")

        retry_strategy = Retry(backoff_factor=1, total=3)
        adapter = HTTPAdapter(max_retries=retry_strategy)

        self.http_session = requests.Session()
        self.http_session.mount("https://", adapter)

        self.host = host.Host(self)
        self.zone = zone.Zone(self)
        self.rzone = rzone.RZone(self)
        self.rrset = rrset.RRSet(self)

        self.reload_server = Request(
            base=self.base_url + "web-services/rest/resource/DNSServer",
            filters={"action": "reloadServer"},
            authorization=(self.username, self.password),
            http_session=self.http_session,
        ).action

        self.sync_ha_pair = Request(
            base=self.base_url + "web-services/rest/resource/CCMHaDnsPair",
            filters={"action": "sync"},
            authorization=(self.username, self.password),
            http_session=self.http_session,
        ).action

    def __eq__(self, other):
        if isinstance(other, ElementalDns):
            return self.base_url == other.base_url

        return False

    def __ne__(self, other):
        if isinstance(other, ElementalDns):
            return self.base_url != other.base_url

        return True

    def __hash__(self):
        return hash(repr(self))
