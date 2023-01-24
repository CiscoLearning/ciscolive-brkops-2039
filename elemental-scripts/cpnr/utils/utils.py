from elemental_utils import ElementalNetbox, ElementalDns, DAC, ElementalCdns
from pynetbox.models.virtualization import VirtualMachines
from pynetbox.core.response import Record
from elemental_utils import cpnr
from typing import List
import concurrent.futures
import logging


def get_dns_server_obj(domain: str, enb: ElementalNetbox, dac: DAC, recurse: bool = True) -> VirtualMachines:
    """Given a domain, return the authoritative DNS server.

    Args:
        :domain str: Domain name
        :enb ElementalNetbox: ElementalNetbox object for querying NetBox
        :dac DAC: DNS as Code object for additional DNS parameters
        :recurse bool: Whether or not to recurse (default: True)

    Returns:
        :VirtualMachines: A NetBox VirtualMachine object representing the authoritative DNS server or None if the DNS server cannot be found
    """
    tenants = enb.tenancy.tenants.all()

    for tenant in tenants:
        primary_domain = dac.get_primary_domain(None, tenant)
        if not primary_domain:
            continue

        if primary_domain == domain:
            auth_dns = enb.virtualization.virtual_machines.get(tenant_id=tenant.id, status="active", role="auth-dns-primary")
            if auth_dns:
                return auth_dns

        # Find the auth DNS for aliased zones.  This assumes the aliased zones end with a '.'.
        if primary_domain.rstrip(".") in dac.dns_parameters.zone_map:
            for zone in dac.dns_parameters.zone_map[primary_domain.rstrip(".")]:
                auth_dns = None
                if domain == zone:
                    auth_dns = enb.virtualization.virtual_machines.get(tenant_id=tenant.id, status="active", role="auth-dns-primary")

                if auth_dns:
                    return auth_dns

    # We have to loop twice to prevent returning an ancillary domain when a primary exists.
    if recurse:
        zm = dac.dns_parameters.zone_map
        for tenant in tenants:
            if tenant.custom_fields:
                tenant_domain = tenant.custom_fields.get("DNS Domain")
                if tenant_domain and tenant_domain in zm:
                    for zone in zm[tenant_domain]:
                        if zone.endswith("."):
                            # Ignore aliased zones that are fully-qualified.
                            continue

                        aux_pd = dac.get_primary_domain(zone, tenant)
                        if domain == aux_pd:
                            return get_dns_server_obj(domain=dac.get_primary_domain(tenant_domain, tenant), enb=enb, dac=dac, recurse=False)

    return None


def get_dns_server(domain: str, enb: ElementalNetbox, dac: DAC, recurse: bool = True) -> str:
    """Given a domain, return the IP address of the authoritative DNS server.

    Args:
        :domain str: Domain name
        :enb ElementalNetbox: ElementalNetbox object for querying NetBox
        :dac DAC: DNS as Code object for additional DNS parameters
        :recurse bool: Whether or not to recurse (default: True)

    Returns:
        :str: IP address of the authoritative DNS server or None if the DNS server cannot be found
    """
    auth_dns = get_dns_server_obj(domain, enb, dac, recurse)
    if auth_dns:
        if auth_dns.primary_ip4:
            return auth_dns.primary_ip4.address.split("/")[0]

    return None


def determine_auth_dns(tenant: Record, enb: ElementalNetbox, dac: DAC) -> VirtualMachines:
    """Given a NetBox Tenant, determine the correct authoritative DNS server.

    Args:
        :tenant Record: NetBox record representing a Tenant object
        :enb ElementalNetbox: ElementalNetbox object for querying NetBox
        :dac DAC: DNS as Code object for additional DNS parameters

    Returns:
        :VirtualMachines: A VirtualMachine object representing the authoritative DNS or None
    """
    logger = logging.getLogger(__name__)
    auth_dns = enb.virtualization.virtual_machines.get(tenant_id=tenant.id, status="active", role="auth-dns-primary")
    if not auth_dns:
        auth_domain = dac.get_primary_domain(None, tenant)
        if auth_domain:
            auth_dns = get_dns_server_obj(auth_domain, enb, dac)
        if not auth_dns:
            logger.info(f"⛔️ No primary DNS server for {tenant.name}")
            return None

    if not auth_dns.primary_ip4:
        logger.warning(f"⛔️ No primary IPv4 address for DNS server {auth_dns.name} for {tenant.name}")
        return None

    return auth_dns


def normalize_cnames(cnames: List[str], domain: str) -> List[str]:
    """
    Given a list of CNAMEs, ensure each one is stripped, ends with a '.'
    and has the default domain name if another domain name is not present.

    Args:
        :cnames List[str]: List of CNAMEs to normalize
        :domain str: Default domain name to append to unqualified CNAMEs

    Returns:
        :List[str]: Normalized list of CNAMEs
    """

    cnames = [s.strip() for s in cnames]
    cnames = list(map(lambda s: s + "." if ("." in s and not s.endswith(".")) else s, cnames))
    cnames = list(map(lambda s: s + f".{domain}" if (not s.endswith(".")) else s, cnames))

    return cnames


def dedup_cnames(cnames: List[str], domain: str) -> List[str]:
    """
    Ensure a list of CNAMEs is unique

    Args:
        :cnames List[str]: List of CNAMEs to check
        :domain str: Domain name to append to those unqualified CNAMEs

    Returns:
        :List[str]: De-duped list of CNAMEs
    """
    cname_dict = {}
    cname_list = normalize_cnames(cnames, domain)
    for c in cname_list:
        cname_dict[c] = True

    return list(cname_dict.keys())


def get_ecdnses(nb_obj: VirtualMachines, site_name: str, enb: ElementalNetbox) -> List[ElementalCdns]:
    """Get a list of caching DNS servers.

    Args:
        :nb_obj VirtualMachines: NetBox VirtualMachines object in the same site as the CDNS servers
        :site_name str: NetBox site name
        :enb ElementalNetbox: ElementalNetbox object

    Returns:
        :list: List of ElementalCdns objects
    """
    cdnses = []
    cdns_vms = enb.virtualization.virtual_machines.filter(site_id=nb_obj.site.id, status="active", role="caching-dns")
    for cdns_vm in cdns_vms:
        cdnses.append(ElementalCdns(url=f"https://{cdns_vm.primary_ip4.address.split('/')[0]}:8443/", site=site_name))

    return cdnses


def get_cname_record(
    alias: str, domain: str, enb: ElementalNetbox, dac: DAC, edns_hash: dict, ecdns_hash: dict
) -> cpnr.models.model.Record:
    """Get a CNAME RRSet if it exists.

    Args:
        :alias str: Alias for which to search
        :domain str: Domain name in which to look for the CNAME alias
        :enb ElementalNetbox: ElementalNetbox object to query for auth DNS
        :dac DAC: DNS as Code object

    Returns:
        :Record: Resource Record set if CNAME is found else (or if auth DNS cannot be found) None
    """
    logger = logging.getLogger(__name__)
    if domain not in edns_hash:
        auth_dns = get_dns_server_obj(domain, enb, dac)
        if not auth_dns:
            # XXX: Move this back to warning once everything is properly setup.
            logger.info(f"⛔️ Unable to find auth DNS for domain {domain}")
            return None

        edns_hash[domain] = ElementalDns(
            url=f"https://{auth_dns.primary_ip4.address.split('/')[0]}:8443/", site=str(auth_dns.tenant.group.parent).lower()
        )

        if auth_dns.site.id not in ecdns_hash:
            ecdns_hash[auth_dns.site.id] = get_ecdnses(auth_dns, str(auth_dns.tenant.group.parent).lower(), enb)

    edns = edns_hash[domain]

    return edns.rrset.get(alias, zoneOrigin=domain)


def launch_parallel_task(
    task, task_name: str, iterator: list, name_attribute: str, workers: int = 20, stop_on_error: bool = False, /, *args
) -> bool:
    """Execute a parallel task using thread pools.

    Args:
        :task (function): Task/function to execute
        :task_name str: Description of the task
        :iterator list: List of items on which to run the task
        :name_attribute str: Name of the attribute to identify the item
        :workers int: Number of threads to use (default: 20)
        :stop_on_error bool: Whether to stop if an error is encountered (default: False)
        :*args: Arguments to the task

    Returns:
        :bool: True if the task succeeded, False otherwise
    """
    logger = logging.getLogger(__name__)
    result = True
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_task = {executor.submit(task, item, *args): item for item in iterator}
        for ft in concurrent.futures.as_completed(future_task):
            item = future_task[ft]
            try:
                ft.result()
            except Exception as e:
                if not name_attribute:
                    logger.exception(f"⛔️ Failed to {task_name} for {item}: {e}")
                else:
                    logger.exception(f"⛔️ Failed to {task_name} for {getattr(item, name_attribute)}: {e}")
                result = False
                if stop_on_error:
                    break

    return result


def restart_dns_servers(edns_hash: dict, edns_modified: dict, cdnses: dict) -> None:
    """Restart all affected DNS servers.

    Args:
        :edns_hash dict: Dict of domains and their respective ElementalDns objects
        :edns_modified dict: Dict of ElementalDns objects that have been modified
        :cdnses dict: Dict of NetBox site IDs to ElementalCdns objects
    """
    logger = logging.getLogger(__name__)
    restarted = []
    for edns in edns_hash.values():
        if edns not in restarted and edns in edns_modified:
            try:
                edns.sync_ha_pair(instance="DNSHA", add_params={"mode": "exact", "direction": "fromMain"})
            except Exception:
                # This can fail when we don't yet have an HA pair.
                pass
            edns.reload_server()
            restarted.append(edns)
            logger.info(f"🏁 Reloaded server {edns.base_url}")

    if len(restarted) > 0:
        # Only restart CDNSes if an auth DNS was restarted.
        for cdns_set in cdnses.values():
            # Restart each applicable CDNS server.
            for cdns in cdns_set:
                cdns.reload_server()
                logger.info(f"🏁 Reloaded CDNS server {cdns.base_url}")


def get_reverse_zone(ip: str) -> str:
    """Get the reverse zone for an IP.

    Args:
        :ip str: IP address to parse

    Returns:
        :str: Reverse zone name
    """
    octets = ip.split(".")
    rzone_name = f"{'.'.join(octets[::-1][1:])}.in-addr.arpa."

    return rzone_name


def parse_txt_record(txt_record: str) -> dict:
    """Parse a NetBox TXT record and return a dict of it.

    Args:
        :txt_record str: String representation of the TXT record data

    Returns:
        :dict: Dict of the results with each field a key
    """
    result = {}

    txt_record = txt_record.strip('"')
    if not txt_record.startswith("v=_netbox"):
        raise ValueError(f"Invalid NetBox TXT record data: {txt_record}")

    key_vals = txt_record.split(" ")
    for key_val in key_vals:
        (key, value) = key_val.split("=")
        result[key] = value

    return result
