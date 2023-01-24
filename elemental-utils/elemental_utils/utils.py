import os
import subprocess
import sys
import json
from typing import List, Tuple


def check_environment(*args):
    """
    Check that all the expected environment variables have been set.
    """

    envvars = list(map(os.environ.get, args))

    if not all(envvars):
        raise KeyError(f"One or more of {', '.join(args)} are not set in the environment")


def delete_vm(vcenter: str, datacenter: str, cluster: str, name: str, folder: str = None) -> Tuple[bool, str]:
    """
    Run Ansible to delete a VM from vCenter
    """

    results = []

    os.environ["ANSIBLE_FORCE_COLOR"] = "True"
    os.environ["ANSIBLE_HOST_KEY_CHECKING"] = "False"
    os.environ["ANSIBLE_PERSISTENT_COMMAND_TIMEOUT"] = "600"

    command = [
        "ansible-playbook",
        "-e",
        f"vm_name={name}",
        "-e",
        f"vcenter={vcenter}",
        "-e",
        f"datacenter={datacenter}",
        "-e",
        f"cluster={cluster}",
        "-e",
        f"ansible_python_interpreter={sys.executable}",
    ]

    if folder:
        command += ["-e", f"folder={folder}"]

    command.append(os.path.join(os.path.dirname(__file__), "ansible/delete-vm.yaml"))

    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in iter(lambda: p.stdout.readline(), b""):
        results.append(line.decode("utf-8"))

    p.wait()

    if p.returncode != 0:
        return (False, "".join(results))

    return (True, None)


def deploy_vm_from_ova(
    vcenter: str, datacenter: str, cluster: str, datastore: str, ova: str, name: str, portgroup: str, folder: str = None
) -> Tuple[bool, str]:
    """
    Run Ansible to spin up a VM from an OVA in vCenter
    """

    results = []

    os.environ["ANSIBLE_FORCE_COLOR"] = "True"
    os.environ["ANSIBLE_HOST_KEY_CHECKING"] = "False"
    os.environ["ANSIBLE_PERSISTENT_COMMAND_TIMEOUT"] = "600"

    command = [
        "ansible-playbook",
        "-e",
        f"vm_name={name}",
        "-e",
        f"vm_ova={ova}",
        "-e",
        f"vm_network={portgroup}",
        "-e",
        f"vcenter={vcenter}",
        "-e",
        f"datacenter={datacenter}",
        "-e",
        f"cluster={cluster}",
        "-e",
        f"datastore={datastore}",
        "-e",
        f"ansible_python_interpreter={sys.executable}",
    ]

    if folder:
        command += ["-e", f"folder={folder}"]

    command.append(os.path.join(os.path.dirname(__file__), "ansible/deploy-vm-ova.yaml"))

    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in iter(lambda: p.stdout.readline(), b""):
        results.append(line.decode("utf-8"))

    p.wait()

    if p.returncode != 0:
        return (False, "".join(results))

    """

    print("\nINFO: Getting IPs for new VAs...")

    os.environ["ANSIBLE_CONFIG"] = "ansible/info.ansible.cfg"

    command = [
        "ansible-playbook",
        "-i",
        inventory_file,
        "ansible/get-vm-info.yaml",
    ]

    results.clear()
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for line in iter(lambda: p.stdout.readline(), b""):
        results.append(line.decode("utf-8"))

    p.wait()
    del os.environ["ANSIBLE_CONFIG"]

    j = json.loads("".join(results))
    ips = [None, None]

    if p.returncode != 0:
        return (False, j["plays"][0]["tasks"][0]["hosts"]["localhost"]["msg"])

    for vm in j["plays"][0]["tasks"][0]["hosts"]["localhost"]["virtual_machines"]:
        if vm["guest_name"] == name + "-01":
            ips[0] = vm["ip_address"]
        elif vm["guest_name"] == name + "-02":
            ips[1] = vm["ip_address"]

        if ips[0] and ips[1]:
            break

    """

    return (True, None)


def deploy_vm_from_tmpl(
    vcenter: str,
    datacenter: str,
    cluster: str,
    datastore: str,
    template: str,
    name: str,
    portgroup: str,
    ip: str,
    netmask: str,
    gateway: str,
    domain: str,
    dns_servers: List[str],
    folder: str = None,
    dns_search: List[str] = None,
) -> Tuple[bool, str]:
    """
    Run Ansible to spin up a VM from a template in vCenter
    """

    results = []

    os.environ["ANSIBLE_FORCE_COLOR"] = "True"
    os.environ["ANSIBLE_HOST_KEY_CHECKING"] = "False"
    os.environ["ANSIBLE_PERSISTENT_COMMAND_TIMEOUT"] = "600"

    command = [
        "ansible-playbook",
        "-e",
        f"vm_name={name}",
        "-e",
        f"vm_template={template}",
        "-e",
        f"vm_network={portgroup}",
        "-e",
        f"vcenter={vcenter}",
        "-e",
        f"datacenter={datacenter}",
        "-e",
        f"cluster={cluster}",
        "-e",
        f"datastore={datastore}",
        "-e",
        f"vm_ip={ip}",
        "-e",
        f"vm_netmask={netmask}",
        "-e",
        f"vm_gateway={gateway}",
        "-e",
        f'{{"dns_servers": {json.dumps(dns_servers)}}}',
        "-e",
        f"dns_domain={domain}",
        "-e",
        f"ansible_python_interpreter={sys.executable}",
    ]

    if folder:
        command += ["-e", f"folder={folder}"]

    if dns_search:
        command += ["-e", f'{{"dns_search": {json.dumps(dns_search)}}}']

    command.append(os.path.join(os.path.dirname(__file__), "ansible/deploy-vm-template.yaml"))

    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in iter(lambda: p.stdout.readline(), b""):
        results.append(line.decode("utf-8"))

    p.wait()

    if p.returncode != 0:
        return (False, "".join(results))

    return (True, None)


def deploy_vm_from_tmpl_no_custom(
    vcenter: str,
    datacenter: str,
    cluster: str,
    datastore: str,
    template: str,
    name: str,
    portgroup: str,
    folder: str = None,
) -> Tuple[bool, str]:
    """
    Run Ansible to spin up a VM from a template in vCenter without any customization
    """

    results = []

    os.environ["ANSIBLE_FORCE_COLOR"] = "True"
    os.environ["ANSIBLE_HOST_KEY_CHECKING"] = "False"
    os.environ["ANSIBLE_PERSISTENT_COMMAND_TIMEOUT"] = "600"

    command = [
        "ansible-playbook",
        "-e",
        f"vm_name={name}",
        "-e",
        f"vm_template={template}",
        "-e",
        f'vm_network="{portgroup}"',
        "-e",
        f"vcenter={vcenter}",
        "-e",
        f"datacenter={datacenter}",
        "-e",
        f"cluster={cluster}",
        "-e",
        f"datastore={datastore}",
        "-e",
        f"ansible_python_interpreter={sys.executable}",
    ]

    if folder:
        command += ["-e", f"folder={folder}"]

    command.append(os.path.join(os.path.dirname(__file__), "ansible/deploy-vm-template-no-custom.yaml"))

    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in iter(lambda: p.stdout.readline(), b""):
        results.append(line.decode("utf-8"))

    p.wait()

    if p.returncode != 0:
        return (False, "".join(results))

    return (True, None)


def execute_vm_script(
    vcenter: str,
    datacenter: str,
    name: str,
    script: str,
    arguments: str,
    environment: List[str] = [],
    folder: str = None,
) -> Tuple[bool, str]:
    """
    Use Ansible to run a script via vCenter on a VM
    """

    results = []

    os.environ["ANSIBLE_FORCE_COLOR"] = "True"
    os.environ["ANSIBLE_HOST_KEY_CHECKING"] = "False"
    os.environ["ANSIBLE_PERSISTENT_COMMAND_TIMEOUT"] = "600"

    command = [
        "ansible-playbook",
        "-e",
        f"vm_name={name}",
        "-e",
        f"vcenter={vcenter}",
        "-e",
        f"datacenter={datacenter}",
        "-e",
        f"script_name={script}",
        "-e",
        f'{{"script_arguments": "{arguments}"}}',
        "-e",
        f'{{"script_environment": {json.dumps(environment)}}}',
        "-e",
        f"ansible_python_interpreter={sys.executable}",
    ]

    if folder:
        command += ["-e", f"folder={folder}"]

    command.append(os.path.join(os.path.dirname(__file__), "ansible/execute-vm-script.yaml"))

    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in iter(lambda: p.stdout.readline(), b""):
        results.append(line.decode("utf-8"))

    p.wait()

    if p.returncode != 0:
        return (False, "".join(results))

    return (True, None)


def add_vm_disk(
    vcenter: str,
    datacenter: str,
    name: str,
    size: int,
    unit: int,
    folder: str = None,
) -> Tuple[bool, str]:
    """
    Use Ansible to add a disk to a VM
    """

    results = []

    os.environ["ANSIBLE_FORCE_COLOR"] = "True"
    os.environ["ANSIBLE_HOST_KEY_CHECKING"] = "False"
    os.environ["ANSIBLE_PERSISTENT_COMMAND_TIMEOUT"] = "600"

    command = [
        "ansible-playbook",
        "-e",
        f"vm_name={name}",
        "-e",
        f"vcenter={vcenter}",
        "-e",
        f"datacenter={datacenter}",
        "-e",
        f"disk_size={size}",
        "-e",
        f"disk_unit={unit}",
        "-e",
        f"ansible_python_interpreter={sys.executable}",
    ]

    if folder:
        command += ["-e", f"folder={folder}"]

    command.append(os.path.join(os.path.dirname(__file__), "ansible/add-vm-disk.yaml"))

    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in iter(lambda: p.stdout.readline(), b""):
        results.append(line.decode("utf-8"))

    p.wait()

    if p.returncode != 0:
        return (False, "".join(results))

    return (True, None)
