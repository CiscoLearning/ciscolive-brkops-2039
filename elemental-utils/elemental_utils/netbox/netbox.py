from typing import Dict
import pynetbox
from pynetbox.models.virtualization import VirtualMachines
from pynetbox.models.dcim import Devices, Cables
from pynetbox.models.ipam import IpAddresses
from pynetbox.core.response import Record
import os
import ipaddress


class NoSuchObjectError(Exception):
    pass


class DuplicateObjectError(Exception):
    pass


class ElementalNetbox(object):
    _type_map = {
        "vm": "virtualization.virtual_machines",
        "device": "dcim.devices",
        "cable": "dcim.cables",
    }

    def __init__(self, netbox_address=None, netbox_api_token=None):
        """
        Class for wrapping pynetbox to provide Elemental convenience.

        :param netbox_address: Optional URL for NetBox (if omitted, it is taken from the environment)
        :param netbox_api_token: Optional API token (it omitted, it is taken from the environment)
        """

        if not netbox_address:
            netbox_address = os.environ.get("NETBOX_ADDRESS")

        if not netbox_api_token:
            netbox_api_token = os.environ.get("NETBOX_API_TOKEN")

        if not netbox_address or not netbox_api_token:
            raise Exception(
                "Missing NetBox address and/or API token.  Either pass them to the constructor, or set NETBOX_ADDRESS and NETBOX_API_TOKEN "
                "in the environment."
            )

        self._nb = pynetbox.api(netbox_address, netbox_api_token)
        try:
            self._nb.status()
        except Exception as e:
            raise Exception(f"Failed to connect to Netbox: '{e}'")

    @property
    def nb(self):
        """
        Get the direct Netbox handle
        """
        return self._nb

    @property
    def dcim(self):
        """
        Get the DCIM attribute from the Netbox API
        """
        return self._nb.dcim

    @property
    def ipam(self):
        """
        Get the IPAM attribute from the Netbox API
        """
        return self._nb.ipam

    @property
    def circuits(self):
        """
        Get the Circuits attribute from the Netbox API
        """
        return self._nb.circuits

    @property
    def secrets(self):
        """
        Get the Secrets attribute from the Netbox API
        """
        return self._nb.secrets

    @property
    def tenancy(self):
        """
        Get the Tenancy attribute from the Netbox API
        """
        return self._nb.tenancy

    @property
    def extras(self):
        """
        Get the Extras attribute from the Netbox API
        """
        return self._nb.extras

    @property
    def virtualization(self):
        """
        Get the Virtualization attribute from the Netbox API
        """
        return self._nb.virtualization

    @property
    def users(self):
        """
        Get the Users attribute from the Netbox API
        """
        return self._nb.users

    def __resolve_type(self, ntype):
        # Float KeyErrors northbound
        class_path = ElementalNetbox._type_map[ntype].split(".")
        klass = self._nb
        for elem in class_path:
            klass = getattr(klass, elem)

        return klass

    def update_status(self, name: str, ntype: str, status: str = "active") -> None:
        """
        Update a object's status in Netbox

        :param name: Name of NetBox object for which its status will be changed
        :param ntype: Type of NetBox object this named element is
        :param status: Status string to set
        """

        try:
            klass = self.__resolve_type(ntype.lower())
        except KeyError:
            raise KeyError(f"Failed to a matching Netbox class for type {ntype}")

        nb_obj = klass.get(name=name)
        if not nb_obj:
            raise NoSuchObjectError(f"Failed to find object {name} of type {ntype}")

        nb_obj.status = status
        nb_obj.save()

    def _get_site_tenant(self, site_name, tenant_name, naz):
        """
        Get Site and Tenant objects
        """

        site = self.dcim.sites.get(name=site_name)
        if not site:
            return (None, None)

        tenant_group = self.tenancy.tenant_groups.get(name=site_name.lower() + f"-z{naz}")
        if not tenant_group:
            return (site, None)

        tenant = self.tenancy.tenants.get(group=tenant_group.slug, name=tenant_name)

        return (site, tenant)

    def get_ip(self, ip: str, netmask: str, vrf: str, tenant: str) -> IpAddresses:
        """
        Get an IP object and its network given an address and mask

        :param ip: IP address to fetch from NetBox
        :param netmask: Netmask for IP
        :param vrf: NetBox VRF for the IP address
        :param tenant: NetBox tenant in which to look for the IP address
        :return IP address object from NetBox
        """

        network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
        ip_obj = ipaddress.ip_address(ip)
        tenant = self.tenancy.tenants.get(name=tenant)
        vrf = self.ipam.vrfs.get(name=vrf)
        nb_ip = self.ipam.ip_addresses.get(
            tenant_id=tenant.id,
            address=f"{ip_obj.compressed}/{network.prefixlen}",
            vrf_id=vrf.id,
        )

        return nb_ip

    def add_ip(self, ip: str, netmask: str, vrf: str, tenant: str, dns_name: str = None) -> IpAddresses:
        """
        Add an IP address object for a given IP, netmask, VRF, and tenant

        :param ip: IP address to add to NetBox
        :param netmask: Netmask for this IP
        :param vrf: NetBox VRF in which this IP will reside
        :param tenant: Tenant that owns this IP address
        :param dns_name: DNS name for this IP address
        :return The resulting NetBox IP address object
        """

        ip_obj = ipaddress.ip_address(ip)
        network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
        tenant = self.tenancy.tenants.get(name=tenant)
        vrf = self.ipam.vrfs.get(name=vrf)
        nb_ip = self.ipam.ip_addresses.create(
            tenant=tenant.id,
            address=f"{ip_obj.compressed}/{network.prefixlen}",
            vrf=vrf.id,
        )

        if dns_name:
            nb_ip.dns_name = dns_name
            nb_ip.description = dns_name
            nb_ip.save()

        return nb_ip

    def connect_devices(
        self, device_a: str, int_a: str, device_b: str, int_b: str, status: str = "connected", ttype: str = "dcim.interface", **kwargs
    ) -> Cables:
        """
        Connect two devices given device names and interface names

        :param device_a: Name of first device to connect
        :param int_a: Name of interface on first device to connect
        :param device_b: Name of second device to connect
        :param int_b: Name of interface on second device to connect
        :param status: Status string of the resulting connection
        :param ttype: Type of the resulting connection
        :param **kwargs: Additional parameters for the connection can be specified as desired
        :return A NetBox Cable object representing the connection
        """

        supported_versions = {
            "2.10": self._connect_devices_nb2_10,
            "3.3": self._connect_devices_nb3_3,
        }
        netbox_version = self.nb.status()["netbox-version"]
        netbox_major_minor_version = f"{netbox_version.split('.')[0]}.{netbox_version.split('.')[1]}"

        # NetBox version changes in Cable Model
        if netbox_major_minor_version not in supported_versions:
            raise ValueError(f"NetBox Version {netbox_version} not supported by this method.")

        return supported_versions[netbox_major_minor_version](device_a, int_a, device_b, int_b, status, ttype, **kwargs)

    def _connect_devices_nb2_10(
        self, device_a: str, int_a: str, device_b: str, int_b: str, status: str = "connected", ttype: str = "dcim.interface", **kwargs
    ) -> Cables:
        """
        NetBox Version 2.10.4 method version

        Connect two devices given device names and interface names

        :param device_a: Name of first device to connect
        :param int_a: Name of interface on first device to connect
        :param device_b: Name of second device to connect
        :param int_b: Name of interface on second device to connect
        :param status: Status string of the resulting connection
        :param ttype: Type of the resulting connection
        :param **kwargs: Additional parameters for the connection can be specified as desired
        :return A NetBox Cable object representing the connection
        """

        try:
            dev_a_obj = self.dcim.devices.get(name=device_a)
        except Exception as e:
            raise ValueError(f"unable to resolve device_a {device_a}: {e}")

        try:
            device_b_obj = self.dcim.devices.get(name=device_b)
        except Exception as e:
            raise ValueError(f"unable to resolve device_b {device_b}: {e}")

        try:
            int_a_obj = self.dcim.interfaces.get(device_id=dev_a_obj.id, name=int_a)
        except Exception as e:
            raise ValueError(f"unable to resolve interface {int_a} for device {device_a}: {e}")

        try:
            int_b_obj = self.dcim.interfaces.get(device_id=device_b_obj.id, name=int_b)
        except Exception as e:
            raise ValueError(f"unable to resolve interface {int_b} for device {device_b}: {e}")

        try:
            nb_cable = self.dcim.cables.create(
                status=status,
                termination_a_id=int_a_obj.id,
                termination_a_type=ttype,
                termination_b_id=int_b_obj.id,
                termination_b_type=ttype,
                **kwargs,
            )
        except Exception as e:
            raise ValueError(f"unable to create cable between {device_a}:{int_a}<>{device_b}{int_b}: {e}")

        return nb_cable

    def _connect_devices_nb3_3(
        self, device_a: str, int_a: str, device_b: str, int_b: str, status: str = "connected", ttype: str = "dcim.interface", **kwargs
    ) -> Cables:
        """
        NetBox Version 3.3.4 method version

        Connect two devices given device names and interface names

        :param device_a: Name of first device to connect
        :param int_a: Name of interface on first device to connect
        :param device_b: Name of second device to connect
        :param int_b: Name of interface on second device to connect
        :param status: Status string of the resulting connection
        :param ttype: Type of the resulting connection
        :param **kwargs: Additional parameters for the connection can be specified as desired
        :return A NetBox Cable object representing the connection
        """

        try:
            dev_a_obj = self.dcim.devices.get(name=device_a)
        except Exception as e:
            raise ValueError(f"unable to resolve device_a {device_a}: {e}")

        try:
            device_b_obj = self.dcim.devices.get(name=device_b)
        except Exception as e:
            raise ValueError(f"unable to resolve device_b {device_b}: {e}")

        try:
            int_a_obj = self.dcim.interfaces.get(device_id=dev_a_obj.id, name=int_a)
        except Exception as e:
            raise ValueError(f"unable to resolve interface {int_a} for device {device_a}: {e}")

        try:
            int_b_obj = self.dcim.interfaces.get(device_id=device_b_obj.id, name=int_b)
        except Exception as e:
            raise ValueError(f"unable to resolve interface {int_b} for device {device_b}: {e}")

        try:
            nb_cable = self.dcim.cables.create(
                status=status,
                a_terminations=[
                    {
                        "object_type": ttype,
                        "object_id": int_a_obj.id,
                    },
                ],
                b_terminations=[
                    {
                        "object_type": ttype,
                        "object_id": int_b_obj.id,
                    },
                ],
                **kwargs,
            )

        except Exception as e:
            raise ValueError(f"unable to create cable between {device_a}:{int_a}<>{device_b}{int_b}: {e}")

        return nb_cable

    def add_device(
        self,
        name: str,
        dtype: str,
        site_name: str,
        naz: str,
        tenant_name: str,
        vrf_name: str,
        mgmt_intf: str,
        ip: str,
        netmask: str,
        role: str,
        platform: str,
        allow_duplicates: bool = False,
        status: str = "planned",
        manuf_name: str = "Cisco",
    ) -> Devices:
        """
        Add a device to Netbox using Elemental rules.

        :param name: Name of the device to add
        :param dtype: Type of the device to add
        :param site_name: Name of the site into which the device will be placed
        :param naz: Network availability zone identifier for this device
        :param tenant_name: Name of the tenant that will own this device
        :param vrf_name: Name of the VRF which will hold this device's IP
        :param mgmt_intf: Name of the primary management interface of this device
        :param ip: IP address of the management interface
        :param netmask: Netmask of the management interface IP
        :param role: Role name for this device
        :param platform: NetBox platform (i.e., software version) for this device
        :param allow_duplicates: Whether or not to allow for duplicate device names
        :param status: Status of the device when it's added
        :param manuf_name: Manufacturer name for the device
        :return A NetBox Device object
        """

        (site, tenant) = self._get_site_tenant(site_name, tenant_name, naz)
        if not site:
            raise NoSuchObjectError(f"Invalid site name {site}")

        if not tenant:
            raise NoSuchObjectError(f"Invalid tenant {tenant_name} in NAZ {naz} for site {site_name}")

        nb_dev = self.dcim.devices.get(name=name, tenant_id=tenant.id)
        if nb_dev and not allow_duplicates:
            raise DuplicateObjectError(f"Device {name} already exists in tenant {tenant_name}")
        elif not nb_dev:
            dev_role = self.dcim.device_roles.get(name=role)
            if not dev_role:
                raise NoSuchObjectError(f"Invalid device role {role}")

            dev_platform = self.dcim.platforms.get(name=platform)
            if not dev_platform:
                raise NoSuchObjectError(f"Invalid device platform {platform}")

            manuf = self.dcim.manufacturers.get(name=manuf_name)
            if not manuf:
                raise NoSuchObjectError(f"Invalid manufacturer name {manuf_name}")

            dev_type = self.dcim.device_types.get(model=dtype)
            if not dev_type:
                raise NoSuchObjectError(f"Invalid device type {dtype}")

            vrf = self.ipam.vrfs.get(name=vrf_name)
            if not vrf:
                raise NoSuchObjectError(f"Invalid VRF {vrf}")

            nb_mgmt_ip = self.get_ip(ip, netmask, vrf, tenant)
            if not nb_mgmt_ip:
                nb_mgmt_ip = self.add_ip(ip, netmask, vrf, tenant, name)

            nb_dev = self.dcim.devices.create(
                name=name,
                device_role=dev_role.id,
                platform=dev_platform.id,
                manufacturer=manuf.id,
                device_type=dev_type.id,
                site=site.id,
                status=status,
                tenant=tenant.id,
            )

        nb_mgmt_intf = self.dcim.interfaces.get(name=mgmt_intf, device_id=nb_dev.id)
        if not nb_mgmt_intf:
            # Delete the device since we can't pre-check the right interface.
            # This lets someone re-run the method once they fix the interface name.
            nb_dev.delete()
            raise NoSuchObjectError(f"Invalid management interface for device type {dtype}")

        if not nb_mgmt_ip.assigned_object or nb_mgmt_ip.assigned_object.id != nb_mgmt_intf.id:
            nb_mgmt_ip.assigned_object_id = nb_mgmt_intf.id
            nb_mgmt_ip.assigned_object_type = "dcim.interface"
            nb_mgmt_ip.save()

        nb_dev.primary_ip4 = nb_mgmt_ip.id
        nb_dev.save()

        return nb_dev

    def add_vm(
        self,
        name: str,
        site_name: str,
        naz: str,
        tenant_name: str,
        cluster: str,
        vrf_name: str,
        interface: str,
        ip: str,
        netmask: str,
        vcpus: int,
        ram: int,
        disk: int,
        role: str,
        platform: str,
        allow_duplicates: bool = False,
        status: str = "planned",
    ) -> VirtualMachines:
        """
        Add a VM to Netbox following the Elemental rules

        :param name: Name of the VM to add
        :param site_name: Name of the site into which to put the VM
        :param naz: Network Availability Zone identifier for this VM
        :param tenant_name: Name of the tenant that will own this VM
        :param cluster: VMware cluster into which this VM will be placed
        :param vrf_name: Name of the NetBox VRF that will hold this VM's IP
        :param interface: Name of the primary interface for this VM
        :param ip: IP address of the primary interface for this VM
        :param netmask: Netmask for the primary IP
        :param vcpus: Number of virtual CPUs this VM will have
        :param ram: Amount of RAM in megabytes that this VM will have
        :param disk: Amount of disk space in gigabytes that this VM will have
        :param role: Role name for this VM
        :param platform: NetBox platform (i.e., software version) for this VM
        :param allow_duplicates: Whether or not to allow duplicate VMs
        :param status: Status of the resulting VM
        :return A NetBox VirtualMachine object
        """

        (site, tenant) = self._get_site_tenant(site_name, tenant_name, naz)
        if not site:
            raise NoSuchObjectError(f"Invalid site name {site}")

        if not tenant:
            raise NoSuchObjectError(f"Invalid tenant {tenant_name} in NAZ {naz} for site {site_name}")

        # Check if VM already exists
        nb_vm = self.virtualization.virtual_machines.get(name=name, tenant_id=tenant.id)
        if nb_vm and not allow_duplicates:
            raise DuplicateObjectError(f"VM {name} already exists in tenant {tenant_name}")
        elif not nb_vm:
            vm_role = self.dcim.device_roles.get(name=role)
            if not vm_role:
                raise NoSuchObjectError(f"Invalid VM role {role}")

            vm_platform = self.dcim.platforms.get(name=platform)
            if not vm_platform:
                raise NoSuchObjectError(f"Invalid VM platform {platform}")

            vm_cluster = self.virtualization.clusters.get(name=cluster, site=site.slug)
            if not vm_cluster:
                raise NoSuchObjectError(f"Invalid VM cluster {cluster} for site {site_name}")

            vrf = self.ipam.vrfs.get(name=vrf_name)
            if not vrf:
                raise NoSuchObjectError(f"Invalid VRF {vrf}")

            nb_mgmt_ip = self.get_ip(ip, netmask, vrf, tenant)
            if not nb_mgmt_ip:
                nb_mgmt_ip = self.add_ip(ip, netmask, vrf, tenant, name)

            nb_vm = self.virtualization.virtual_machines.create(
                tenant=tenant.id,
                site=site.id,
                role=vm_role.id,
                cluster=vm_cluster.id,
                platform=vm_platform.id,
                vcpus=vcpus,
                memory=ram,
                disk=disk,
                name=name,
                status=status,
            )

        nb_vm_intf = self.virtualization.interfaces.get(virtual_machine_id=nb_vm.id, name=interface)
        if not nb_vm_intf:
            nb_vm_intf = self.virtualization.interfaces.create(virtual_machine=nb_vm.id, name=interface)

        if not nb_mgmt_ip.assigned_object or nb_mgmt_ip.assigned_object.id != nb_vm_intf.id:
            nb_mgmt_ip.assigned_object_id = nb_vm_intf.id
            nb_mgmt_ip.assigned_object_type = "virtualization.vminterface"
            nb_mgmt_ip.save()

        nb_vm.primary_ip4 = nb_mgmt_ip.id
        nb_vm.save()

        return nb_vm

    def get_vm(self, name: str) -> Dict:
        """
        Get a VM from Netbox

        :param name: Name of the VM to get
        :return A dictionary
        """

        nb_vm_intf_data = []

        nb_vm = self.virtualization.virtual_machines.get(name=name)
        nb_vm_intf = self.virtualization.interfaces.filter(virtual_machine_id=nb_vm.id)

        if not nb_vm:
            raise NoSuchObjectError(f"VM {name} does not exist")

        if not nb_vm_intf:
            raise NoSuchObjectError(f"VM {name} does not have any interfaces")

        for intf in nb_vm_intf:
            nb_vm_intf_data.append(intf.name)

        nb_vm_data = {
            "name": nb_vm.name,
            "site": nb_vm.site,
            "tenant": nb_vm.tenant,
            "primary_ip4": nb_vm.primary_ip4,
            "interfaces": nb_vm_intf_data,
        }

        return nb_vm_data

    def get_device(self, name: str) -> Dict:
        """
        Get a device from Netbox

        :param name: Name of the device to get
        :return A dictionary
        """
        nb_dev = self.dcim.devices.get(name=name)

        dev_mgmt_ip = self.ipam.ip_addresses.get(device_id=nb_dev.id)

        nb_dev_intf_data = []

        nb_dev_intf = self.dcim.interfaces.filter(device_id=nb_dev.id)

        if not nb_dev:
            raise NoSuchObjectError(f"Device {name} does not exist")

        if not nb_dev_intf:
            raise NoSuchObjectError(f"Device {name} does not have any interfaces")

        for intf in nb_dev_intf:
            nb_dev_intf_data.append(intf.name)

        nb_dev_data = {
            "name": nb_dev.name,
            "site": nb_dev.site,
            "tenant": nb_dev.tenant,
            "primary_ip4": nb_dev.primary_ip4,
            "management_ip": dev_mgmt_ip,
            "interfaces": nb_dev_intf_data,
        }

        return nb_dev_data
