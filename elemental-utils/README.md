# Elemental Utils

This repository includes a set of Python classes and utilities for automating aspects of the Elemental Project.

To install run:

```bash
python -m pip install git+https://gitlab.systems.cll.cloud/jclarke/elemental-utils.git
```

## Elemental Netbox

The Elemental Netbox class contains methods for interacting with Netbox in adherence with the Elemental rules.  While
the general `pynetbox` library is generally sufficient for queries, adding certain elements require some specific
steps.

To use Elemental Netbox, first set the environment variable `NETBOX_ADDRESS` to the URL for Netbox and `NETBOX_API_TOKEN` to your Netbox API
key.  Then do the following:

```python
from elemental_utils import ElementalNetbox

enb = ElementalNetbox()
```

From here, you can access the typical `pynetbox` attributes such as `dcim`, `ipam`, etc. directly using the `enb` object.  The interesting methods specific to
`ElementalDns` are as follows.

### `add_device`

The `add_device` method adds a device object to Netbox following the guidelines in [Confluence](https://confluence.certsite.net/confluence/display/NEXT/Workflow%3A+Creating+New+NetBox+Device).
To use this method, do the following:

```python
nb_dev = enb.add_device(
    name="tst01-z0-my-device",
    dtype="Nexus 9336",
    site_name="TST01",
    naz="0",
    tenant_name="tst01-admin",
    vrf_name="cll-global",
    mgmt_intf="mgmt0",
    ip="10.224.0.123",
    netmask="255.255.254.0",
    role="Distribution Switch",
    platform="nxos.9.3.6",
    allow_duplicates=False,
    status="planned",
    manuf_name="Cisco",
)
```

The `allow_duplicates` defaults to `False` and will trigger a `ElementalNetbox.DuplicateObjectError` if the object already exists in Netbox.  If `True` the object's management interface will be adjusted per
the other Elemental rules.  The properties `status` and `manuf` have defaults "planned" and "Cisco" respectively.  All other properties are required.

The `nb_dev` return value will be a Netbox device object.  If an error occurrs an Exception will be raised (either NoSuchObjectError or ValueError) with additional details.
If any of the steps fail, the device will not be in Netbox inventory.  So the error can be corrected, and `add_device` can be re-run.

### `add_vm`

The `add_vm` method adds a virtual machine (VM) object to Netbox following the guidelines in [Confluence](https://confluence.certsite.net/confluence/display/NEXT/Workflow%3A+Creating+New+NetBox+Virtual+Machine?src=contextnavpagetreemode).
To use this method, do the following:

```python
try:
    nb_vm = enb.add_vm(
        name="tst01-z0-vm-my-vm",
        site_name="TST01",
        naz="0",
        tenant_name="tst01-admin",
        cluster="tst01-host-esxi-cluster-01",
        vrf_name="cll-global",
        interface="ens160",
        ip="10.224.0.123",
        netmask="255.255.254.0",
        vcpus="1",
        ram="8192", # MB
        disk="10", # GB
        allow_duplicates=False,
        role="General Infrastructure VM",
        platform="cpnr.10.1.1",
        status="planned",
    )
except Exception:
    pass
```

The `allow_duplicates` defaults to `False` and will trigger a `ElementalNetbox.DuplicateObjectError` if the object already exists in Netbox.  If `True` the object's management interface will be adjusted per
the other Elemental rules.  The `role` attribute defaults to "Infrastructure VM".  The `status` property defaults to "planned".  All other properties are required.

If the method is successful he `nb_vm` return value will be a Netbox device object.  If an error occurs an Exception will be raised (either NoSuchObjectError or DuplicateObjectError) with additional details.

_TODO: Should we add a property for additional interfaces?_

### `update_status`

The `update_status` method updates an object's status in Netbox.  To use this method, do the following:

```python
enb.update_status(name="tst01-z0-vm-my-vm", ntype="vm", status="active")
```

The `status` property is optional and defaults to "active" and must be a string representing a known Netbox status.  If an error occurs (such as an invalid `ntype` value) an Exception will be raised.

### `add_ip`

The `add_ip` method adds an IP address object to Netbox.  This happens automatically when adding devices or VMs, but it might be useful to call directly.  To use this method, do the following:

```python
try:
    nb_ip = enb.add_ip(
        ip="10.224.0.123",
        netmask="255.255.254.0",
        vrf="cll-global",
        tenant="tst01-admin",
        dns_name="tst01-z0-vm-my-vm"
    )
except Exception:
    pass
```

The `dns_name` property is optional and defaults to `None`.  If an error occurs (such as an IP/netmask that doesn't have a known prefix), an Exception will be raised.  Else, the method
will return the IP address object.

### `connect_devices`

The `connect_devices` method creates a cable object between two devices given the device and interface names.  To use this method, do the following:

```python
try:
    nb_cable = enb.connect_devices(
        device_a="tst01-z0-fw-admin-01",
        int_a="GigabitEthernet0/1",
        device_b="tst01-z0-sw-naz-aggr-01",
        int_b="Ethernet1/1",
        status="connected",
        ttype="dcim.interface",
        **kwargs,
    )
except Exception:
    pass
```

The `status` and `ttype` arguments are optional and default to the values shown above (the first 't' in `ttype` means "termination").  This method also accepts an optional `**kwargs`
dict for any additional cable parameters that Netbox supports.

### `get_vm`

The `get_vm` method fetches data about a VM from NetBox.  To use this method, do the following:

```python
try:
    nb_vm = enb.get_vm(
        name="tst01-z0-vm-admin-auth-dns-01",
    )
except Exception:
    pass
```

This method returns a Python dictionary with preselected fields, you can access any key by using Python dictionary notation `nb_vm["primary_ip4"]`

```python
{
    'name': 'tst01-z0-vm-admin-auth-dns-01',
    'primary_ip4': 10.224.0.12/23,
    'site': TST01,
    'tenant': tst01-z0-admin,
    'interfaces': ['ens160']
 }
```

### `get_device`

The `get_device` method fetches data about a VM from NetBox.  To use this method, do the following:

```python
try:
    nb_dev = enb.get_device(
        name="tst01-z0-fw-admin-01",
    )
except Exception:
    pass
```

This method returns a Python dictionary with preselected fields, you can access any key by using Python dictionary notation `nb_dev["management_ip"]`

```python
{
    'name': 'tst01-z0-fw-admin-01',
    'management_ip': 10.224.128.25/23,
    'primary_ip4': None,
    'site': TST01,
    'tenant': tst01-z0-admin,
    'interfaces': ['GigabitEthernet0/1',
                    'GigabitEthernet0/2',
                    'GigabitEthernet0/3',
                    'GigabitEthernet0/4',
                    'GigabitEthernet0/5',
                    'GigabitEthernet0/6',
                    'Management0/0']
}
```


## Elemental DNS

The Elemental DNS class contains methods for interacting with Cisco Prime Network Registrar's DNS and caching DNS services.  This library implements a
thin layer over the REST API that is built into CPNR.

To use Elemental DNS, first set the environment variable `CPNR_USERNAME` to the desired CPNR username and `CPNR_PASSWORD` to that user's password (note: while a read-only
user will work, full functionality requires an administrator).  Then do the following:

```python
from elemental_utils import ElementalDns

edns = ElementalDns(domain=DOMAIN)
```

Here, `DOMAIN` represents a domain (more precisely, zone) you wish to manage.  Elemental DNS will then use the Start Of Authority record to find the correct DNS
server.  This is the typical use case for Elemental.

However, if you'd rather specify a DNS server explicitly, then omit the `domain` attribute and specify `url=URL` where `URL` is the protocol, IP/hostname, and port
number of the desired DNS server.

### Object Methods

Each attribute of the `edns` object represents a specific API endpoint in CPNR.  With each, you can typically execute the following methods: `get()`, `all()`, `filter()`,
`add()`, `update()`, `delete()`.  The `get()` method retrieves data about one specific instance of an object whereas the `all()` method returns all instances of said object.
The `filter()` method allows you to perform a more granular query.  The `add()`, `update()`, and `delete()` methods will in the Create, Update, and Delete functions of the CRUD
paradigm.

**NOTE:** Most properties support regular expression matching when used as filter parameters.  This may cause your queries to match more than you intended unless you use anchors.  
For example, to get details for a single zone named "test01.infra.cll.cloud", use `origin="^test01.infra.cll.cloud."`; or, in this case, leaving out the `origin=` will
trigger a key-based search.  With keys, the name is matched exactly, so anchors are not required.

Many queries return an object of type `Record`.  This is nothing more than a thin wrapper on top of `dict`.  While you can access the results as a Python dictionary, you
can also treat dictionary keys as attributes of the `Record` object.  Therefore, you can access the `addrs` key of a `host` record as `h.addrs` or `h["addrs"]`.  **CAUTION**:
This attribute referencing only works for the _first_ level.  Subsequent-level dictionaries must be accessed using dictionary key notation.

The object returned from a query, create, or update operation can be modified and its `save()` method can be called to trigger an update in CPNR.

The Elemental DNS object itself has an additional action element called `reload_server()`.  When this is invoked, the DNS server will be reloaded triggering a re-read of
the new zone properties.

#### Required Filter Fields

Each object type generally has a key (unique identifier) as well as one or more mandatory fields to specify a scope or zone for the objects.  If these mandatory fields
are omitted, and exception will be thrown.  For example, the `host` object requires the `zoneOrigin` field to be specified.

### `edns.host`

The `host` attribute of Elemental DNS allows for the querying, creating, updating, and deleting of host objects (i.e., both A and PTR records).  The key field for
`host` is **name** and the required filter field is **zoneOrigin**.  Here is an example using `host`.

```python
# Get one host.
h = edns.host.get("joe-test", zoneOrigin="test01.infra.cll.cloud")
pprint.pprint(h)
r"""
===> {'_Record__api': <elemental_utils.cpnr.dns.ElementalDns object at 0x10b0c8f40>,
 '_Record__ref': <class 'elemental_utils.cpnr.models.host.Host'>,
 'addrs': {'stringItem': ['1.1.1.3']},
 'name': 'joe-test',
 'objectOid': 'OID-00:00:00:00:00:00:02:4b',
 'tenantId': '0',
 'zone': 'OID-00:00:00:00:00:00:00:52',
 'zoneOrigin': 'test01.infra.cll.cloud.'}
"""

# Update host IP.
h.addrs = {"stringItem": ["1.1.1.2"]}
h.save()
pprint.pprint(h)
r"""
===> {'_Record__api': <elemental_utils.cpnr.dns.ElementalDns object at 0x10b0c8f40>,
 '_Record__ref': <class 'elemental_utils.cpnr.models.host.Host'>,
 'addrs': {'stringItem': ['1.1.1.2']},
 'name': 'joe-test',
 'objectOid': 'OID-00:00:00:00:00:00:02:4b',
 'tenantId': '0',
 'zone': 'OID-00:00:00:00:00:00:00:52',
 'zoneOrigin': 'test01.infra.cll.cloud.'}
"""

# Delete the host.
h.delete()
h = edns.host.get(name="joe-test", zoneOrigin="test01.infra.cll.cloud")
pprint.pprint(h)
r"""
===> None
"""

# Add a new host.
h = edns.host.add(name="joe-test", zoneOrigin="test01.infra.cll.cloud", addrs={"stringItem": ["1.1.1.4"]})
pprint.pprint(h)
r"""
===> {'_Record__api': <elemental_utils.cpnr.dns.ElementalDns object at 0x105022670>,
 '_Record__ref': <class 'elemental_utils.cpnr.models.host.Host'>,
 'addrs': {'stringItem': ['1.1.1.4']},
 'name': 'joe-test',
 'objectOid': 'OID-00:00:00:00:00:00:02:4c',
 'tenantId': '0',
 'zone': 'OID-00:00:00:00:00:00:00:52',
 'zoneOrigin': 'test01.infra.cll.cloud.'}
"""
```

### `edns.zone`

The `zone` attribute of Elemental DNS allows for the querying, creating, updating, and deleting of zone objects (i.e., both A and PTR records).  The key field for
`zone` is **origin** and does not require any filter fields.  Here is an example using `zone`.

```python
# Get one zone.
z = edns.zone.get("test01.infra.cll.cloud.")
pprint.pprint(z)
r"""
===> '_Record__api': <elemental_utils.cpnr.dns.ElementalDns object at 0x105022670>,
 '_Record__ref': <class 'elemental_utils.cpnr.models.zone.Zone'>,
 'defttl': '24h',
 'expire': '1w',
 'minttl': '10m',
 'nameservers': {'stringItem': ['ns01.test01.infra.cll.cloud.']},
 'ns': 'ns01.test01.infra.cll.cloud.',
 'objectOid': 'OID-00:00:00:00:00:00:00:52',
 'origin': 'test01.infra.cll.cloud.',
 'person': 'jclarke.cisco.com.',
 'refresh': '3h',
 'retry': '60m',
 'serial': '12',
 'tenantId': '0',
 'updateAcl': '10.224.0.0/16',
 'viewId': '0'}
"""

# Update a zone.
z.updateAcl = "10.224.0.0/24"
z.save()
pprint.print(z)
r"""
===> {'_Record__api': <elemental_utils.cpnr.dns.ElementalDns object at 0x105022670>,
 '_Record__ref': <class 'elemental_utils.cpnr.models.zone.Zone'>,
 'defttl': '24h',
 'expire': '1w',
 'minttl': '10m',
 'nameservers': {'stringItem': ['ns01.test01.infra.cll.cloud.']},
 'ns': 'ns01.test01.infra.cll.cloud.',
 'objectOid': 'OID-00:00:00:00:00:00:00:52',
 'origin': 'test01.infra.cll.cloud.',
 'person': 'jclarke.cisco.com.',
 'refresh': '3h',
 'retry': '60m',
 'serial': '12',
 'tenantId': '0',
 'updateAcl': '10.224.0.0/24',
 'viewId': '0'}
"""

# Add a new zone.
z = edns.zone.add(origin="joe-test.cll.cloud.", ns="ns01.test01.cll.cloud.", 
    nameservers={"stringItem": ["ns01.test01.infra.cll.cloud."]}, 
    person="jclarke.cisco.com.", serial="2021030701")
pprint.pprint(z)
r"""
===> '_Record__api': <elemental_utils.cpnr.dns.ElementalDns object at 0x10a04f910>,
 '_Record__ref': <class 'elemental_utils.cpnr.models.zone.Zone'>,
 'defttl': '24h',
 'expire': '1w',
 'minttl': '10m',
 'nameservers': {'stringItem': ['ns01.test01.infra.cll.cloud.']},
 'ns': 'ns01.test01.cll.cloud.',
 'objectOid': 'OID-00:00:00:00:00:00:02:4d',
 'origin': 'joe-test.cll.cloud.',
 'person': 'jclarke.cisco.com.',
 'refresh': '3h',
 'retry': '60m',
 'serial': '2021030701',
 'tenantId': '0'}
"""

# Delete the newly created zone.
z.delete()
r"""
===> True
"""
```

### `edns.rzone`

The `rzone` attribute of Elemental DNS allows for the querying, creating, updating, and deleting of reverse zone objects (i.e., both A and PTR records).  The key field for
`rzone` is **origin** and does not require any filter fields.  Here is an example using `rzone`.

```python
# Get one reverse zone.
rz = edns.rzone.get("224.10.in-addr.arpa.")
pprint.pprint(rz)
r"""
===> {'_Record__api': <elemental_utils.cpnr.dns.ElementalDns object at 0x10a04f910>,
 '_Record__ref': <class 'elemental_utils.cpnr.models.rzone.RZone'>,
 'defttl': '24h',
 'expire': '1w',
 'minttl': '10m',
 'nameservers': {'stringItem': ['ns01.test01.infra.cll.cloud.']},
 'ns': 'ns01.test01.infra.cll.cloud.',
 'objectOid': 'OID-00:00:00:00:00:00:00:67',
 'origin': '224.10.in-addr.arpa.',
 'person': 'jclarke.cisco.com.',
 'refresh': '3h',
 'retry': '60m',
 'serial': '1',
 'tenantId': '0',
 'updateAcl': '10.224.0.0/16',
 'viewId': '0'}
"""

# Update a reverse zone.
rz.updateAcl = "10.224.0.0/24"
rz.save()
pprint.print(rz)
r"""
===> {'_Record__api': <elemental_utils.cpnr.dns.ElementalDns object at 0x10a04f910>,
 '_Record__ref': <class 'elemental_utils.cpnr.models.rzone.RZone'>,
 'defttl': '24h',
 'expire': '1w',
 'minttl': '10m',
 'nameservers': {'stringItem': ['ns01.test01.infra.cll.cloud.']},
 'ns': 'ns01.test01.infra.cll.cloud.',
 'objectOid': 'OID-00:00:00:00:00:00:00:67',
 'origin': '224.10.in-addr.arpa.',
 'person': 'jclarke.cisco.com.',
 'refresh': '3h',
 'retry': '60m',
 'serial': '1',
 'tenantId': '0',
 'updateAcl': '10.224.0.0/24',
 'viewId': '0'}
"""

# Add a new reverse zone.
rz = edns.rzone.add(origin="joe-test.cll.cloud.", ns="ns01.test01.cll.cloud.", 
    nameservers={"stringItem": ["ns01.test01.infra.cll.cloud."]}, 
    person="jclarke.cisco.com.", serial="2021030701")
pprint.pprint(z)
r"""
{'_Record__api': <elemental_utils.cpnr.dns.ElementalDns object at 0x10a04f910>,
 '_Record__ref': <class 'elemental_utils.cpnr.models.rzone.RZone'>,
 'defttl': '24h',
 'expire': '1w',
 'minttl': '10m',
 'nameservers': {'stringItem': ['ns01.test01.infra.cll.cloud.']},
 'ns': 'ns01.test01.cll.cloud.',
 'objectOid': 'OID-00:00:00:00:00:00:02:4e',
 'origin': '1.in-addr.arpa.',
 'person': 'jclarke.cisco.com.',
 'refresh': '3h',
 'retry': '60m',
 'serial': '2021030701',
 'tenantId': '0'}
"""

# Delete the newly created reverse zone.
rz.delete()
r"""
===> True
"""
```

### `edns.rrset`

The `rrset` attribute of Elemental DNS allows for the querying, creating, updating, and deleting of resource record set objects (i.e., both A and PTR records).  The key field for
`rrset` is **name** and the required filter field is **zoneOrigin**.  Here is an example using `rrset`.

```python
# Get one resource record set.
rr = edns.rrset.get("_ldap._tcp.Default-First-Site-Name._sites")
pprint.pprint(rr)
r"""
===> {'_Record__api': <elemental_utils.cpnr.dns.ElementalDns object at 0x10a04f910>,
 '_Record__ref': <class 'elemental_utils.cpnr.models.rrset.RRSet'>,
 'axfrVersion': '0',
 'hits': '0',
 'hostHealthCheck': 'off',
 'lastAccessTime': 'none',
 'lastResetTime': 'none',
 'name': '_ldap._tcp.Default-First-Site-Name._sites',
 'objectOid': 'OID-00:00:00:00:00:00:00:27',
 'protectedState': 'unprotected',
 'rrList': {'CCMRRItem': [{'axfrVersion': '0',
                           'order': '0',
                           'rdata': '0 100 389 '
                                    'tst01-z0-ad-01.test01.infra.cll.cloud.',
                           'rrClass': 'IN',
                           'rrType': 'SRV',
                           'timestamp': 'Sun Mar  7 14:49:38 2021',
                           'ttl': '10m',
                           'weight': '1'}]},
 'tenantId': '0',
 'zone': 'OID-00:00:00:00:00:00:00:52',
 'zoneOrigin': 'test01.infra.cll.cloud.'}
"""

# Update the resource record set.
rr.rrList["CCMRRItem"][0]["ttl"] = "20m"
rr.save()
pprint.print(rr)
r"""
===> {'_Record__api': <elemental_utils.cpnr.dns.ElementalDns object at 0x10f8b24f0>,
 '_Record__ref': <class 'elemental_utils.cpnr.models.rrset.RRSet'>,
 'axfrVersion': '0',
 'hits': '0',
 'hostHealthCheck': 'off',
 'lastAccessTime': 'none',
 'lastResetTime': 'none',
 'name': '_ldap._tcp.Default-First-Site-Name._sites',
 'objectOid': 'OID-00:00:00:00:00:00:00:27',
 'protectedState': 'unprotected',
 'rrList': {'CCMRRItem': [{'axfrVersion': '0',
                           'order': '0',
                           'rdata': '0 100 389 '
                                    'tst01-z0-ad-01.test01.infra.cll.cloud.',
                           'rrClass': 'IN',
                           'rrType': 'SRV',
                           'timestamp': 'Sun Mar  7 15:49:39 2021',
                           'ttl': '20m',
                           'weight': '1'}]},
 'tenantId': '0',
 'zone': 'OID-00:00:00:00:00:00:00:52',
 'zoneOrigin': 'test01.infra.cll.cloud.'}
"""

# Add a new resource record set.
rr = edns.rrset.add(name="joe-test-rr", 
    rrList={"CCMRRItem": [{"rdata": "This is some text", "rrClass": "IN", "rrType": "TXT"}]}, 
    zoneOrigin="test01.infra.cll.cloud.")
r"""
===> {'_Record__api': <elemental_utils.cpnr.dns.ElementalDns object at 0x10f8b24f0>,
 '_Record__ref': <class 'elemental_utils.cpnr.models.rrset.RRSet'>,
 'axfrVersion': '0',
 'hits': '0',
 'hostHealthCheck': 'off',
 'lastAccessTime': 'none',
 'lastResetTime': 'none',
 'name': 'joe-test-rr',
 'objectOid': 'OID-00:00:00:00:00:00:00:70',
 'protectedState': 'protected',
 'rrList': {'CCMRRItem': [{'axfrVersion': '0',
                           'order': '0',
                           'rdata': '"This" "is" "some" "text"',
                           'rrClass': 'IN',
                           'rrType': 'TXT',
                           'timestamp': 'Sun Mar  7 16:03:03 2021',
                           'ttl': '-1',
                           'weight': '1'}]},
 'tenantId': '0',
 'zone': 'OID-00:00:00:00:00:00:00:52',
 'zoneOrigin': 'test01.infra.cll.cloud.'}
"""

# Delete the resource record set.
rr.delete()
r"""
===> True
"""
```
