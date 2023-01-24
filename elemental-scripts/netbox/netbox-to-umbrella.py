#!/usr/bin/env python

from elemental_utils import ElementalNetbox
from elemental_utils.utils import check_environment
from typing import List, Dict
import os
import logging.config
import logging
from logzero import setup_logger
import umbr_api

logging.config.fileConfig(os.path.realpath(os.path.dirname(os.path.realpath(__file__)) + "/../logger_no_webex.conf"))
logger = setup_logger()
logger.setLevel(logging.INFO)

GLOBAL_VRF = "cll-global"


def truncate_network_name(name: str, suffix: int = None) -> str:
    """
    Truncate an internal network name to work with Umbrella

    :param name: Name to possibly truncate
    :param suffix: Optional suffix to apply
    :return truncated name
    """
    trunc_name = name[0:50]

    if suffix:
        ssuffix = "." + str(suffix)
        endl = 50 - len(ssuffix)
        trunc_name = name[0:endl] + ssuffix

    name = trunc_name

    return name


def get_network_name(name: str, int_networks: List[Dict]) -> str:
    """
    Return a unique internal network name

    :param name: Candidate network name
    :param int_networks: List of internal networks
    :return unique new network name
    """

    suffix = None
    net_name = name
    while True:
        net_name = truncate_network_name(name, suffix)
        if not any(d["name"] == net_name for d in int_networks):
            break

        if not suffix:
            suffix = 1
        else:
            suffix += 1

    return net_name


def create_all_sites(prefixes: List, umbr_cred: str, umbr_sites: List[Dict]) -> int:
    """
    Create any NetBox site that is missing in Umbrella

    :param prefixes: List of NetBox IP address prefixes
    :param umbr_cred: Credential to use to login to the Umbrella API
    :param umbr_sites: List of current Umbrella sites
    """

    errors = 0

    for prefix in prefixes:
        if not prefix.vrf:
            continue

        # Prefer to name sites based on the VRF name.  However, if the VRF name is the global VRF, then use
        # the tenant name instead.
        site_name = prefix.vrf.name

        if site_name == GLOBAL_VRF:
            site_name = prefix.tenant.name

        if not any(d["name"] == site_name for d in umbr_sites):
            new_site = umbr_api.management.add_site(name=site_name, orgid=os.environ["UMBRELLA_ORGID"], cred=umbr_cred)
            if new_site.status_code != 200:
                logger.warning(f"⛔️ Failed to create new Umbrella site {site_name}: {new_site.json()}")
                errors += 1
                continue

            logger.info(f"🎨 Created Umbrella site {site_name}")
            umbr_sites.append(new_site.json())

    return errors


def main():
    try:
        check_environment("NETBOX_ADDRESS", "NETBOX_API_TOKEN", "UMBRELLA_ORGID", "UMBRELLA_KEY", "UMBRELLA_SECRET")
    except KeyError as e:
        logger.error(f"🚨 {e}")
        exit(1)

    errors = 0

    umbr_cred = f"{os.environ['UMBRELLA_KEY']}:{os.environ['UMBRELLA_SECRET']}"

    umbr_sites = umbr_api.management.sites(orgid=os.environ["UMBRELLA_ORGID"], cred=umbr_cred, console=False, page=-1, limit=200)
    umbr_int_networks = umbr_api.management.internalnetworks(
        orgid=os.environ["UMBRELLA_ORGID"], cred=umbr_cred, console=False, page=-1, limit=200
    )

    enb = ElementalNetbox()

    nb_prefixes = [prefix for prefix in enb.ipam.prefixes.all() if prefix.tenant and prefix.vlan]
    errors += create_all_sites(prefixes=nb_prefixes, umbr_cred=umbr_cred, umbr_sites=umbr_sites)

    for prefix in nb_prefixes:
        create_new = True
        site_name = prefix.vrf.name
        if site_name == GLOBAL_VRF:
            site_name = prefix.tenant.name

        siteid = [s["siteId"] for s in umbr_sites if s["name"] == site_name][0]

        # We don't want a guaranteed-unique name yet, just one that is the right length.
        # If the name exists and the address/prefix length are the same, don't do anything.
        umbr_name = truncate_network_name(f"{prefix.vlan.name} : {site_name}")
        (addr, plen) = str(prefix).split("/")
        for int_network in umbr_int_networks:
            if int_network["siteId"] == siteid:
                if int_network["name"] == umbr_name:
                    if addr == int_network["ipAddress"] and int(plen) == int(int_network["prefixLength"]):
                        create_new = False

                    break

        if create_new:
            new_net = umbr_api.management.add_internal_network(
                name=umbr_name,
                ipaddress=addr,
                prefixlen=plen,
                siteid=siteid,
                orgid=os.environ["UMBRELLA_ORGID"],
                cred=umbr_cred,
            )
            if new_net.status_code != 200:
                logger.warning(
                    f"⛔️ Failed to create new internal network {umbr_name} with network IP {addr} and prefix length {plen} for site "
                    f"{site_name}: {new_net.json()}"
                )
                errors += 1
                continue

            logger.info(
                f"🎨 Created new Umbrella internal network {umbr_name} with network IP {addr} and prefix length {plen} "
                f"for site {site_name}"
            )
            umbr_int_networks.append(new_net.json())

    exit(errors)


if __name__ == "__main__":
    main()
