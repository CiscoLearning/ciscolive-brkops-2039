#!/usr/bin/env python

from elemental_utils import ElementalDns, ElementalNetbox, DAC
from elemental_utils.cpnr.query import RequestError
from elemental_utils.utils import check_environment

# from elemental_utils.cpnr.query import RequestError
from elemental_utils import cpnr
from utils import (
    determine_auth_dns,
    get_dns_server_obj,
    launch_parallel_task,
    restart_dns_servers,
    get_reverse_zone,
    parse_txt_record,
    get_ecdnses,
)

from pynetbox.core.response import Record

# from pynetbox.models.virtualization import VirtualMachines
from colorama import Fore, Style

from dataclasses import dataclass, field
from threading import Lock
import os
from typing import List

# import ipaddress
import logging.config
import logging
from webex_handler import WebexHandler
import argparse
import sys

# import json
# import hvac

logging.config.fileConfig(os.path.realpath(os.path.dirname(os.path.realpath(__file__)) + "/../logger.conf"))
logger = logging.getLogger(__name__)
logging.addLevelName(WebexHandler.NOTICE, "NOTICE")
for handler in logger.parent.handlers:
    if isinstance(handler, WebexHandler):
        handler.setLevel(WebexHandler.NOTICE)

# Dict to store a mapping of domain to edns object.
EDNS_HASH = {}
# Dict to store a mapping of edns objects to whether or not they were modified.
EDNS_MODIFIED = {}
# Dict to store a mapping of site ID to list of caching DNS servers
ECDNS_HASH = {}


@dataclass
class DnsRecords:
    """Class for tracking DNS records to delete."""

    deletes: List[cpnr.models.model.Record] = field(default_factory=list)
    lock: Lock = Lock()


def get_ptr_rrs(ips: list, edns: ElementalDns) -> List[cpnr.models.model.Record]:
    """Get a list of PTR records for a given set of IP addresses.

    Args:
        :ips list: The IP addresses to process
        :edns ElementalDns: ElementalDns object

    Returns:
        :list: List of RRSet records
    """
    result = []
    for addr in ips:
        rzone = get_reverse_zone(addr)
        ptr_name = addr.split(".")[::-1][0]
        ptr_rrs = edns.rrset.get(ptr_name, zoneOrigin=rzone)
        if ptr_rrs:
            result.append(ptr_rrs)

    return result


def check_record(
    host: cpnr.models.model.Record,
    primary_domain: str,
    rrs: list,
    edns: ElementalDns,
    dac: DAC,
    enb: ElementalNetbox,
    wip_records: DnsRecords,
) -> None:
    """Check if a host record is still valid.

    Args:
        :host Record: Host DNS record
        :primary_domain str: Primary domain name for the hosts
        :rrs list: List of all RRSets
        :edns ElementalDns: ElementalDns object
        :dac DAC: DNS As Code Object
        :enb ElementalNetbox: ElementalNetbox object
        :wip_records DnsRecords: DnsRecords object to hold the records to delete

    """
    # We do not want to operate on the domain itself or the DNS server A records.
    if f"{host.name}.{host.zoneOrigin}" == primary_domain or host.name in (
        "@",
        primary_domain,
        dac.dns_parameters.ns1_name,
        dac.dns_parameters.ns2_name,
    ):
        return

    # Get the RRSet for the host.
    host_rr = None
    for rr in rrs:
        if rr.name == host.name:
            host_rr = rr
            break

    if not host_rr:
        logger.warning(f"🪲 Did not find an RRSet for {host.name}.  This is definitely a bug!")
        return

    found_txt = None
    for rr in host_rr.rrList["CCMRRItem"]:
        if rr["rrType"] == "TXT" and (rr["rdata"].startswith('"v=_netbox') or rr["rdata"].startswith('"v=_static')):
            found_txt = rr["rdata"]
            break

    wip_records.lock.acquire()

    if not found_txt:
        # No TXT record with NetBox data means this host record should be removed.
        wip_records.deletes.append(host_rr)
        # Also remove any PTR records.
        wip_records.deletes.extend(get_ptr_rrs(host.addrs["stringItem"], edns))
    elif found_txt.startswith('"v=_netbox'):
        txt_obj = parse_txt_record(found_txt)
        ip_obj = enb.ipam.ip_addresses.get(int(txt_obj["ip_id"]))
        if not ip_obj:
            # The IP object is gone, so remove this record.
            wip_records.deletes.append(host_rr)
            # Also remove the PTR record
            wip_records.deletes.extend(get_ptr_rrs(host.addrs["stringItem"], edns))

    wip_records.lock.release()


def check_cname(
    rrs: cpnr.models.model.Record,
    primary_domain: str,
    edns: ElementalDns,
    dac: DAC,
    enb: ElementalNetbox,
    wip_records: DnsRecords,
) -> None:
    """Check if a CNAME record is still valid.

    Args:
        :host Record: Host DNS record
        :primary_domain str: Primary domain name for the hosts
        :rrs list: List of all RRSets
        :edns ElementalDns: ElementalDns object
        :dac DAC: DNS As Code object
        :enb ElementalNetbox: ElementalNetbox object
        :wip_records DnsRecords: DnsRecords object to hold the records to delete
    """
    global EDNS_HASH, ECDNS_HASH

    found_host = False
    for rr in rrs.rrList["CCMRRItem"]:
        if rr["rrType"] == "CNAME":
            found_host = rr["rdata"]
            break

    if not found_host:
        # This is not a CNAME, so skip it.
        return

    # Lookup the CNAME target to make sure it's still in DNS.
    domain_parts = found_host.split(".")
    host = domain_parts[0]
    if len(domain_parts) == 1:
        zone = primary_domain
    else:
        zone = ".".join(domain_parts[1:])
    if zone not in EDNS_HASH:
        auth_dns = get_dns_server_obj(zone, enb, dac)
        if not auth_dns:
            logger.warning(f"⛔️ Unable to find auth DNS for domain {zone}")
            return None

        EDNS_HASH[zone] = ElementalDns(
            url=f"https://{auth_dns.primary_ip4.address.split('/')[0]}:8443/", site=str(auth_dns.tenant.group.parent).lower()
        )

        if auth_dns.site.id not in ECDNS_HASH:
            ECDNS_HASH[auth_dns.site.id] = get_ecdnses(auth_dns, str(auth_dns.tenant.group.parent).lower(), enb)

    current_edns = EDNS_HASH[zone]

    host_obj = current_edns.host.get(host, zoneOrigin=zone)
    if not host_obj:
        # The host that this CNAME points to is gone, so delete the CNAME.
        wip_records.lock.acquire()
        wip_records.deletes.append(rrs)
        wip_records.lock.release()


def delete_record(cpnr_record: cpnr.models.model.Record, primary_domain: str, dummy: bool) -> None:
    """Delete a record from CPNR.

    Args:
        :cpnr_record Record: CPNR record to delete
        :primary_domain str: Primary DNS domain
        :dummy bool: Whether a dummy server is being used
    """
    global EDNS_MODIFIED

    name = cpnr_record.name
    domain = cpnr_record.zoneOrigin

    if dummy and domain != primary_domain and "in-addr.arpa." not in domain:
        # We do not do any work except to the dummy server.
        return

    if "in-addr.arpa." in domain:
        edns = EDNS_HASH[primary_domain]
    else:
        edns = EDNS_HASH[domain]

    try:
        cpnr_record.delete()
    except RequestError as e:
        if e.req.status_code != 404:
            # We may end up deleting the same record twice.
            # If it's already gone, don't complain.
            raise
    else:
        logger.log(WebexHandler.NOTICE, f"🧼 Successfully deleted record {name}.{domain}")
        EDNS_MODIFIED[edns] = True


def print_records(wip_records: DnsRecords, tenant: Record) -> None:
    """Print the records to be processed.

    Args:
        :wip_records DnsRecords: DnsRecords object containing the records to process
        :tenant Record: A NetBox Tenant for which this DNS record applies
    """
    print(f"DNS records to be deleted for tenant {tenant.name} ({len(wip_records.deletes)} records):")
    for rec in wip_records.deletes:
        print(f"\t{Fore.RED}DELETE{Style.RESET_ALL} {rec.name}.{rec.zoneOrigin}")


def parse_args() -> object:
    """Parse any command line arguments.

    Returns:
        :object: Object representing the arguments passed
    """
    parser = argparse.ArgumentParser(prog=sys.argv[0], description="Cleanup stale DNS records in CPNR")
    parser.add_argument(
        "--site",
        metavar="<SITE>",
        help="Site to cleanup",
        required=False,
    )
    parser.add_argument(
        "--tenant",
        metavar="<TENANT>",
        help="Tenant to cleanup",
        required=False,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do a dry-run (no changes made)",
        required=False,
    )
    parser.add_argument(
        "--dummy", metavar="<DUMMY SERVER>", help="Override main DNS server with a dummy server (only used with --tenant", required=False
    )

    args = parser.parse_args()

    if args.site and args.tenant:
        print("Only one of --site or --tenant can be given")
        exit(1)

    if not args.site and not args.tenant:
        print("One of --site or --tenant must be provided")
        exit(1)

    if args.dummy and not args.tenant:
        print("--dummy requires --tenant")
        exit(1)

    return args


def main():
    global EDNS_HASH, ECDNS_HASH

    try:
        # TODO Convert this to Vault?
        check_environment("NETBOX_ADDRESS", "NETBOX_API_TOKEN")
    except KeyError as e:
        logger.exception(f"🚨 {e}")
        exit(1)

    try:
        dac = DAC()
    except Exception as e:
        logger.exception(f"🚨 {e}")
        exit(1)

    args = parse_args()

    if args.site:
        lower_site = args.site.lower()
    if args.tenant:
        lower_tenant = args.tenant.lower()

    enb = ElementalNetbox()

    # 1. Get a list of all tenants.  If we work tenant-by-tenant, we will likely remain connected
    #    to the same DNS server.
    tenants = enb.tenancy.tenants.all()
    for tenant in tenants:
        if args.site and str(tenant.group.parent).lower() != lower_site:
            continue

        if args.tenant and tenant.name.lower() != lower_tenant:
            continue
        elif args.tenant:
            lower_site = str(tenant.group.parent).lower()

        if not args.dummy:
            auth_dns = determine_auth_dns(tenant, enb, dac)
            if not auth_dns:
                continue

        primary_domain = dac.get_primary_domain(None, tenant)
        if not primary_domain:
            logger.warning(f"⛔️ Missing DNS domain info for tenant {tenant.name}")
            continue

        if primary_domain in EDNS_HASH:
            # We've already processed DNS for this domain.
            continue

        if not args.dummy:
            EDNS_HASH[primary_domain] = edns = ElementalDns(
                url=f"https://{auth_dns.primary_ip4.address.split('/')[0]}:8443/", site=lower_site
            )

            ECDNS_HASH[auth_dns.site.id] = get_ecdnses(auth_dns, lower_site, enb)

        else:
            EDNS_HASH[primary_domain] = edns = ElementalDns(url=f"https://{args.dummy}:8443/", site=lower_site)

        # 2. Get all host records then all RRSets from CPNR
        hosts = edns.host.all(zoneOrigin=primary_domain)
        if len(hosts) == 0:
            continue
        rrs = edns.rrset.all(zoneOrigin=primary_domain)

        wip_records = DnsRecords()

        # 3. Use thread pools to obtain a list of records to delete.
        launch_parallel_task(
            check_record, "check DNS record(s)", hosts, "name", 20, False, primary_domain, rrs, edns, dac, enb, wip_records
        )

        # 4. Iterate through the RRs looking for stale CNAMEs
        launch_parallel_task(check_cname, "check for stale CNAMEs", rrs, "name", 20, False, primary_domain, edns, dac, enb, wip_records)

        # 5. If doing a dry-run, only print out the changes.
        if args.dry_run:
            print_records(wip_records, tenant)
            continue

        # 6. Process records to be deleted first.  Use thread pools again to parallelize this.
        launch_parallel_task(
            delete_record, "delete DNS record", wip_records.deletes, "name", 20, False, primary_domain, (args.dummy is not None)
        )

    # 7. Restart affected DNS servers.
    if not args.dry_run:
        # Technically nothing is modified in dry-run, but just to be safe.
        restart_dns_servers(EDNS_HASH, EDNS_MODIFIED, ECDNS_HASH)


if __name__ == "__main__":
    main()
