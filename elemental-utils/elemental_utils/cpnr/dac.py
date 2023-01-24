import requests
import yaml
from pynetbox.core.response import Record


class Params(dict):
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


class DAC(object):
    """
    DNS as Code class for reading DNS config to drive a DaC workflow.
    """

    DNS_AS_CODE_CFG = "https://gitlab.systems.cll.cloud/jclarke/dns-as-code/-/raw/master/dns-config.yaml"

    def __init__(self):
        r = requests.get(DAC.DNS_AS_CODE_CFG)
        try:
            r.raise_for_status()
        except Exception as e:
            raise Exception(f"Failed to load DNS as Code config: {e}: {r.text}")

        try:
            conf_obj = yaml.safe_load(r.text)
        except Exception as e:
            raise ValueError(f"Failed to process DNS as Code config: {e}: {r.text}")

        if "vm_parameters" not in conf_obj:
            raise KeyError("Failed to find 'vm_parameters' in DNS as Code config")

        if "dns_parameters" not in conf_obj:
            raise KeyError("Failed to find 'dns_parameters' in DNS as Code config")

        self.vm_parameters = Params(conf_obj["vm_parameters"])
        self.dns_parameters = Params(conf_obj["dns_parameters"])

    def is_ad_domain(self, domain: str) -> bool:
        """
        Determine if a domain will host AD services.
        Returns: (bool) True if AD services are hosted, False otherwise
        """

        dparts = domain.split(".")
        if dparts[0] in self.dns_parameters.ad_prefixes:
            return True

        return False

    def get_ad_domain(self, tenant: Record) -> str:
        """
        Get the fully-qualified AD domain name for a site
        Returns (str): Fully-qualified AD domain name
        """

        dns_name = tenant.custom_fields.get("DNS Name", "prod")
        ad_domain_prefix = self.dns_parameters.ad_prefixes[0]

        return f"{dns_name}.{ad_domain_prefix}.{self.dns_parameters.root_domain}"

    def get_primary_domain(self, domain: str, tenant: Record) -> str:
        """
        Return the primary DNS domain given a domain name (string) and a tenant (Netbox tenant object)
        Returns: (str) expanded primary domain name with trailing '.'
        """

        primary_domain = None

        if not domain:
            if not tenant.custom_fields or "DNS Domain" not in tenant.custom_fields:
                return None

            domain = tenant.custom_fields["DNS Domain"]

        dns_name = tenant.custom_fields.get("DNS Name", "prod")

        dparts = domain.split(".")
        if dparts[0] in self.dns_parameters.ad_prefixes:
            primary_domain = f"{dns_name}.{domain}"
        else:
            primary_domain = domain
            if dns_name != "prod":
                primary_domain = f"{dparts[0]}-{dns_name}.{'.'.join(dparts[1:])}"

        if not primary_domain.endswith("."):
            primary_domain += "."

        return primary_domain
