"""SSH/SCP transport to a jailbroken device.

Two connection styles:
  * USB  — spin up `iproxy <local> 22` and SSH to 127.0.0.1:<local>.
  * Wi-Fi — SSH straight to the device IP on port 22.

Auth is password (default jailbreak root password 'alpine') or a key file.
"""

from __future__ import annotations

import contextlib
import socket
import subprocess
import time
from dataclasses import dataclass, field
from typing import List, Optional

from . import utils
from .utils import IphError

DEFAULT_ROOT_PASSWORD = "alpine"


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@dataclass
class SSHClient:
    host: str = "127.0.0.1"
    port: int = 22
    user: str = "root"
    password: Optional[str] = DEFAULT_ROOT_PASSWORD
    key_file: Optional[str] = None
    _iproxy: Optional[subprocess.Popen] = field(default=None, repr=False)

    # -- common ssh/scp option block -----------------------------------------
    def _base_opts(self) -> List[str]:
        opts = [
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            "-o", "LogLevel=ERROR",
        ]
        if self.key_file:
            opts += ["-i", self.key_file]
        else:
            opts += ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password"]
        return opts

    def _auth_prefix(self) -> List[str]:
        if self.key_file or not self.password:
            return []
        sshpass = utils.which("sshpass")
        if not sshpass:
            raise IphError(
                "password auth needs 'sshpass' (brew install sshpass), or pass --ssh-key."
            )
        return [sshpass, "-p", self.password]

    # -- lifecycle -----------------------------------------------------------
    def start_usb_tunnel(self, device_ssh_port: int = 22) -> None:
        """Forward a local port to the device's SSH port over USB via iproxy."""
        utils.require("iproxy", "brew install libimobiledevice")
        local = _free_port()
        proc = subprocess.Popen(
            ["iproxy", str(local), str(device_ssh_port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._iproxy = proc
        self.host = "127.0.0.1"
        self.port = local
        # Wait for the forwarder to accept connections.
        for _ in range(50):
            with contextlib.suppress(OSError):
                with socket.create_connection((self.host, self.port), timeout=0.5):
                    return
            if proc.poll() is not None:
                raise IphError("iproxy exited early; is the device connected over USB?")
            time.sleep(0.1)
        raise IphError("timed out waiting for iproxy tunnel")

    def close(self) -> None:
        if self._iproxy and self._iproxy.poll() is None:
            self._iproxy.terminate()
            with contextlib.suppress(Exception):
                self._iproxy.wait(timeout=3)
        self._iproxy = None

    def __enter__(self) -> "SSHClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- operations ----------------------------------------------------------
    def check(self) -> None:
        """Verify we can authenticate and run a command."""
        proc = self.exec("echo iph-ok", check=False, capture=True)
        if proc.returncode != 0 or "iph-ok" not in (proc.stdout or ""):
            raise IphError(
                "SSH connection failed. Check that OpenSSH is installed on the "
                "device, the password is correct (default 'alpine'), and the "
                "device is reachable.\n" + (proc.stderr or "").strip()
            )

    def exec(self, command: str, *, check: bool = True, capture: bool = False,
             timeout: Optional[float] = None) -> subprocess.CompletedProcess:
        cmd = self._auth_prefix() + ["ssh"] + self._base_opts() + [
            "-p", str(self.port), f"{self.user}@{self.host}", command,
        ]
        return utils.run(cmd, check=check, capture=capture, timeout=timeout)

    def pull(self, remote: str, local: str, *, check: bool = True) -> subprocess.CompletedProcess:
        cmd = self._auth_prefix() + ["scp"] + self._base_opts() + [
            "-P", str(self.port), "-r", f"{self.user}@{self.host}:{remote}", local,
        ]
        return utils.run(cmd, check=check)

    def push(self, local: str, remote: str, *, check: bool = True) -> subprocess.CompletedProcess:
        cmd = self._auth_prefix() + ["scp"] + self._base_opts() + [
            "-P", str(self.port), "-r", local, f"{self.user}@{self.host}:{remote}",
        ]
        return utils.run(cmd, check=check)
