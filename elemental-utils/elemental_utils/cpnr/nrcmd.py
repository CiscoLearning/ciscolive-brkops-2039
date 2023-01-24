import paramiko
import os
import time
import re
import pysftp
from typing import List

TIMEOUT = 60


class NotLicensedError(Exception):
    pass


class NotConnectedError(Exception):
    pass


class AuthenticationError(Exception):
    pass


class ReadTimeoutException(Exception):
    pass


class CPNRNrcmd(object):
    """
    Class to interact with the nrcmd CLI command on a CPNR server.
    This is useful for performing tasks the REST API cannot do.
    """

    def __init__(
        self, ip, username: str = None, password: str = None, root_password: str = None, port: int = 22, is_regional: bool = False
    ):
        """
        Initialize class to interact with CPNR CLI

        :param ip: IP address of CPNR server
        :param username: Username of an administrative user in CPNR
        :param password: Password of administrative CPNR user
        :param root_password: Password of Linux user, root on the CPNR server
        :param port: Port number of the SSH/SFTP server on the CPNR server
        :param is_regional: Is this CPNR server a regional server or a local server
        """

        try:
            if not username:
                self.username = os.environ["CPNR_USERNAME"]
            else:
                self.username = username

            if not password:
                self.password = os.environ["CPNR_PASSWORD"]
            else:
                self.password = password

            if not root_password:
                self.root_password = os.environ["CPNR_ROOT_PASSWORD"]
            else:
                self.root_password = root_password
        except KeyError as e:
            raise KeyError(f"Parameter {e} must either be set in the environment or passed to the constructor")

        self.ip = ip
        self.port = port

        self._ssh_session = None
        self._ssh_chan = None
        self._connected = False
        self._needs_license = False
        self._regional = is_regional
        if is_regional:
            self._nrcmd_prompt = "nrcmd-R>"
        else:
            self._nrcmd_prompt = "nrcmd>"

    def _send_command(self, command, prompt=r"[#>$]$"):
        self._ssh_chan.sendall(str(command) + "\n")
        time.sleep(0.5)
        output = ""
        i = 0
        while i < TIMEOUT:
            try:
                r = self._ssh_chan.recv(65535)
            except Exception as e:
                raise Exception(f"Error reading from SSH channel (read: '{output}'): {e}")

            if len(r) == 0:
                raise EOFError("Remote host has closed the connection")
            r = r.decode("utf-8", "ignore")

            # Remove ANSI color sequences as they mess up prompt matching.
            remove_ansi = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
            r = remove_ansi.sub("", r)

            output += r
            if re.search(prompt, r.strip()):
                break

            # Send another newline to clear the buffer.
            self._ssh_chan.sendall("\n")

            time.sleep(1)
            i += 1

        if i >= TIMEOUT:
            raise ReadTimeoutException(f"Failed to find '{prompt}' in output '{output}'")

        return output

    def connect(self) -> None:
        """
        Connect to the CPNR server and enter the nrcmd interactive shell.
        """

        if self._connected:
            return

        self._ssh_session = paramiko.SSHClient()
        self._ssh_session.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        self._ssh_session.connect(
            self.ip, port=self.port, username="root", password=self.root_password, timeout=10, allow_agent=False, look_for_keys=False
        )
        self._ssh_chan = self._ssh_session.invoke_shell()
        self._ssh_chan.settimeout(TIMEOUT)

        time.sleep(1)
        command = f"/opt/nwreg2/{'regional' if self._regional else 'local'}/usrbin/nrcmd -N {self.username}"
        if self._regional:
            command += " -R"

        self._send_command(command, prompt=r"assword:")
        output = self._send_command(self.password, prompt=fr"({self._nrcmd_prompt})|(Regional IP address.*\s:)|(license file\s:)|#")
        self._connected = True

        if re.search(r"411 Cluster not properly licensed", output):
            self._needs_license = True
            raise NotLicensedError("Cluster requires license; call license() to licesne it")

        if re.search(r"401 Login Failure", output):
            self.disconnect()
            raise AuthenticationError("Invalid CPNR credentials specified")

    def _get_response(self, command, output, prompt):
        lines = output.split("\n")
        index = 0
        if re.search(r"invalid command line\s", output):
            raise ValueError(f"Invalid command: {command}")

        while index < len(lines):
            if re.search(r"^\d\d\d\s", lines[index]):
                break

            index += 1

        if re.search(r"^302 Not Found", lines[index]):
            return None

        if not re.search(r"^100 Ok", lines[index]):
            if re.search(r"^501 Connection Failure", lines[index]):
                self.disconnect()
                raise NotConnectedError("Server has dropped the connection")

            disconnecting = ""
            if not re.search(prompt, output):
                self.disconnect()
                disconnecting = "; disconnecting"

            raise ValueError(f"Error executing command {command}{disconnecting}: '{output}'")

        index += 1
        normalized_output = re.sub(r"\r\n", "\n", re.sub(r"\r\r", "\r", re.sub(prompt, "", "\n".join(output.split("\n")[index:])))).strip()

        ret = {}
        ptr = ret
        for nline in normalized_output.split("\n"):
            if nline == "":
                continue

            if re.search(r"^\S", nline):
                ret[nline.rstrip(":")] = {}
                ptr = ret[nline.rstrip(":")]
            elif " = " in nline:
                (key, value) = nline.split("=", 1)
                ptr[key.strip()] = value.strip()
            # XXX: Any other line patterns we could see?

        return ret

    def license(self, regional_ip: str, services: List[str], regional_port: int = 1244, license_file: str = None) -> None:
        """
        License a CPNR cluster and enable services.

        :param regional_ip: IP address or hostname of the CPNR regional server
        :param services: List of DNS/DHCP services to license
        :param regional_port: Port number of regional integration
        :param license_file: If licensing a regional server, a license file name must be specified
        """

        if not self._connected:
            raise NotConnectedError("Not connected to CPNR")

        if not self._needs_license:
            raise ValueError("License is not required")

        if self._regional:
            if not license_file:
                raise ValueError("The license_file argument is required when licensing a regional server")

            output = self._send_command(
                os.path.join("/root", os.path.basename(license_file)), prompt=fr"({self._nrcmd_prompt})|(license file\s:)|#"
            )

            if re.search(r"not a valid file", output):
                self.disconnect()
                raise NotLicensedError(f"Failed to license CPNR: '{output}'")

        else:
            self._send_command(regional_ip, prompt=r"SCP Port\s+:")
            self._send_command(str(regional_port), prompt=r"Enter services.*\s:")
            output = self._send_command(",".join(services), prompt=fr"({self._nrcmd_prompt})|(Regional IP address.*\s:)|#")

            if re.search(r"^3\d\d Ok", output.split("\n")[0]):
                raise NotLicensedError(f"Failed to license CPNR: '{output}'")

        self._needs_license = False

        if re.search(r"401 Login Failure", output):
            self.disconnect()
            raise AuthenticationError("Invalid CPNR credentials specified")

        try:
            self._get_response(command="", output=output, prompt=fr"{self._nrcmd_prompt}")
        except ValueError:
            raise ValueError(f"Unknown error logging into nrcmd: '{output}'")

    def upload_file(self, filename: str) -> None:
        """
        Upload a file to the remote CPNR server.  This is typically a license file.

        :param filename: Path to a local file to upload to the CPNR server via SFTP
        """

        if not os.path.isfile(filename):
            raise ValueError(f"{filename} is not a valid file")

        cnopts = pysftp.CnOpts()
        cnopts.hostkeys = None

        with pysftp.Connection(self.ip, port=self.port, username="root", password=self.root_password, cnopts=cnopts) as sftp:
            sftp.put(filename)

    def execute(self, command: str) -> dict:
        """
        Execute an nrcmd command.

        :param command: Command to run within nrcmd
        :return output of command
        """

        if not self._connected:
            raise NotConnectedError("Not connected to CPNR")

        if self._needs_license:
            raise NotLicensedError("Cluster requires license; call license() to license it")

        output = self._send_command(command, prompt=fr"({self._nrcmd_prompt})|#")

        return self._get_response(command=command, output=output, prompt=fr"{self._nrcmd_prompt}")

    def change_password(self, new_password: str, username: str = None) -> None:
        """
        Change the current user's password in CPNR.

        :param new_password: New password to set
        :param username: Username whose password will be changed (defaults to 'admin')
        """

        if not self._connected:
            raise NotConnectedError("Not connected to CPNR")

        if self._needs_license:
            raise NotLicensedError("Cluster requires license; call license() to license it")

        command = "admin admin enterPassword"
        if username:
            command = f"admin {username} enterPassword"

        self._send_command(command, prompt=r"password:")
        output = self._send_command(new_password, prompt=r"verify password:")

        if re.search(r"316 Invalid", output):
            raise ValueError(f"Failed to change password: {output}")

        output = self._send_command(new_password, prompt=fr"({self._nrcmd_prompt})|#")

        if re.search(r"320 AX_SCP_PERMISSION_DENIED", output):
            raise ValueError("Failed to change password; current password is invalid")

        if re.search(r"316 Invalid", output):
            raise ValueError(f"Failed to change passwords: {output}")

        self.password = new_password

    def disconnect(self) -> None:
        """
        Disconnect an nrcmd session
        """

        if not self._connected:
            return

        try:
            self._ssh_session.close()
        except Exception:
            pass

        self._connected = False

    def is_connected(self) -> bool:
        """
        Check if the API is connected to CPNR

        :return True if connected, False otherwise
        """

        if not self._connected:
            return False

        try:
            self.execute("session")
        except NotConnectedError:
            self.disconnect()
            return False

        return True

    def is_licensed(self) -> bool:
        """
        Check if CPNR is licensed

        :return True if licensed, False otherwise
        """

        return not self._needs_license

    def change_root_password(self, new_password: str) -> None:
        """
        Change root's password.

        :param new_password: New password for Linux user root
        """

        if not self._connected:
            raise NotConnectedError("Must be connected to change root's password")

        output = self._send_command("quit")
        if not re.search(r"#$", output.strip()):
            self.disconnect()
            raise Exception("Unable to get to Linux root prompt on CPNR server")

        self._send_command("passwd", prompt=r"New password:")
        self._send_command(new_password, prompt=r"Retype new password:")
        output = self._send_command(new_password, prompt=r"#$|(New password:)")

        if re.search(r"passwords do not match", output):
            self.disconnect()
            raise Exception("Unable to change password")

        self.root_password = new_password
        self.disconnect()
        self.connect()

    def restart_cpnr(self, reconnect: bool = False) -> None:
        """
        Reload the CPNR services.

        :param reconnect: After restarting CPNR should the class reconnect
        """

        if not self._connected:
            raise NotConnectedError("Must be connected to restart")

        output = self._send_command("quit")
        if not re.search(r"#$", output.strip()):
            self.disconnect()
            raise Exception("Unable to get to Linux root prompt on CPNR server")

        output = self._send_command(f"/opt/nwreg2/{'regional' if self._regional else 'local'}/usrbin/cnr_stopstart")
        if not re.search(fr"Starting {'regional' if self._regional else 'local'} CNR cluster with systemctl", output):
            self.disconnect()
            raise Exception(f"Unable to restart CPNR services successfully: {output}")

        self.disconnect()
        if reconnect:
            self.connect()
