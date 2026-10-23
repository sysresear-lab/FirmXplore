"""Bounded userspace and reconstructed-VM worker for isolated_docker.

PRoot supplies guest path translation; Docker namespaces and seccomp provide
the isolation boundary. No daemon socket, writable host mount or host network
is made available to the guest.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import http.client
import gzip
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import signal
import stat
import subprocess
import tarfile
import time

MAX_BYTES = 128 * 1024 * 1024
MAX_MEMBERS = 10000
MAX_MEMBER_BYTES = 32 * 1024 * 1024


def unpack(source: Path, root: Path) -> dict:
    """Extract ordinary data first, then confined links; never create devices."""
    root.mkdir(mode=0o700)
    count = total = 0
    links = []
    skipped = []
    seen = set()
    with tarfile.open(source, 'r|gz') as archive:
        for member in archive:
            count += 1
            parts = PurePosixPath(member.name).parts
            if count > MAX_MEMBERS or not parts or parts[0] != 'rootfs' or '..' in parts or len(parts) > 40:
                raise ValueError('invalid rootfs archive path/member budget')
            relative = Path(*parts[1:])
            target = root / relative
            if target == root:
                if not member.isdir():
                    raise ValueError('rootfs root must be a directory')
                continue
            if str(relative) in seen:
                raise ValueError('duplicate archive member')
            seen.add(str(relative))
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                total += member.size
                if member.size > MAX_MEMBER_BYTES or total > MAX_BYTES:
                    raise ValueError('rootfs expanded byte budget exceeded')
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                remaining = member.size
                with target.open('xb') as output:
                    while remaining:
                        block = stream.read(min(65536, remaining))
                        if not block:
                            raise ValueError('truncated archive member')
                        output.write(block)
                        remaining -= len(block)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
            elif member.issym():
                guest = posixpath.normpath(posixpath.join('/' + relative.parent.as_posix(), member.linkname))
                # Absolute guest links are rewritten to confined relative links.
                destination = root / guest.lstrip('/')
                links.append((target, os.path.relpath(destination, target.parent)))
            else:
                skipped.append(member.name)
    for target, link in links:
        if not target.parent.resolve().is_relative_to(root.resolve()):
            raise ValueError('symlink parent escapes rootfs')
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            raise ValueError('archive link conflicts with an existing entry')
        target.symlink_to(link)
    return {'members': count, 'expanded_bytes': total, 'skipped_special_entries': len(skipped)}


def ensure_runtime_directory(root: Path, relative: str) -> None:
    """Create a runtime directory through confined guest symlinks."""
    root_resolved = root.resolve()
    target = root / relative
    resolved = target.resolve(strict=False)
    if not resolved.is_relative_to(root_resolved):
        raise ValueError(f'runtime directory escapes rootfs: {relative}')
    if target.exists() or target.is_symlink():
        if target.is_symlink():
            resolved.mkdir(parents=True, exist_ok=True)
            return
        if not target.is_dir():
            raise ValueError(f'runtime path is not a directory: {relative}')
        return
    resolved.mkdir(parents=True, exist_ok=True)


def isolation_check() -> dict:
    libc = ctypes.CDLL(None, use_errno=True)
    denied = {}
    for name, call in [
        ('mount', lambda: libc.mount(b'none', b'/tmp', b'tmpfs', 0, None)),
        ('unshare', lambda: libc.unshare(0x10000000)),
    ]:
        ctypes.set_errno(0)
        value = call()
        denied[name] = value == -1 and ctypes.get_errno() in (errno.EPERM, errno.EACCES)
    for name, path in [('read_only_root', '/forbidden-write'), ('read_only_input', '/input/rootfs.tar.gz')]:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        except OSError as exc:
            denied[name] = exc.errno in (errno.EROFS, errno.EACCES, errno.EPERM)
        else:
            os.close(fd)
            denied[name] = False
    interfaces = sorted(p.name for p in Path('/sys/class/net').iterdir())
    denied['loopback_only'] = interfaces == ['lo']
    denied['unprivileged_uid'] = os.getuid() == 65534
    denied['no_new_privileges'] = 'NoNewPrivs:\t1' in Path('/proc/self/status').read_text()
    denied['seccomp_filter'] = 'Seccomp:\t2' in Path('/proc/self/status').read_text()
    if not all(denied.values()):
        raise RuntimeError('worker isolation preflight failed: ' + json.dumps(denied))
    return denied


def read_tail(path: Path, limit=16000) -> str:
    with path.open('rb') as stream:
        stream.seek(max(0, path.stat().st_size - limit))
        return stream.read(limit).decode('utf-8', 'replace')


def run_guest(prefix, args, label, timeout=10, env_extra=None, on_ready=None):
    stdout = Path('/work') / (label + '.stdout')
    stderr = Path('/work') / (label + '.stderr')
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': '/tmp', 'PROOT_NO_SECCOMP': '1',
           'QEMU_STRACE': '1', **(env_extra or {})}
    with stdout.open('wb') as out, stderr.open('wb') as err:
        process = subprocess.Popen(prefix + args, stdout=out, stderr=err, env=env, start_new_session=True)
        timed_out = False
        validation = None
        try:
            if label == 'vm':
                deadline = time.monotonic() + timeout
                while process.poll() is None and time.monotonic() < deadline:
                    text = read_tail(stdout, 65536)
                    if on_ready and re.search(r'(?m)^FIRMXPLORE_VM_PROBE_READY\r?$', text):
                        validation = on_ready()
                        break
                    if 'Kernel panic' in text or 'FIRMXPLORE_VM_COMPLETE' in text:
                        break
                    time.sleep(0.2)
                timed_out = process.poll() is None and time.monotonic() >= deadline
            else:
                process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
    return {'command': prefix + args, 'exit_code': process.returncode, 'timed_out': timed_out,
            'functional_validation': validation,
            'stdout': read_tail(stdout), 'stderr': read_tail(stderr)}


def run_service(prefix):
    outpath, errpath = Path('/work/httpd.stdout'), Path('/work/httpd.stderr')
    observation = {'process_started': False, 'service_alive': False, 'request_sent': False,
                   'response_observed': False, 'ports': [], 'emulation_scope': 'userspace_service'}
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': '/tmp', 'PROOT_NO_SECCOMP': '1'}
    with outpath.open('wb') as out, errpath.open('wb') as err:
        process = subprocess.Popen(prefix + ['/usr/bin/httpd'], stdout=out, stderr=err, env=env, start_new_session=True)
        try:
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                listeners = []
                for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
                    parts = line.split()
                    if parts[3] == '0A':
                        listeners.append(int(parts[1].split(':')[1], 16))
                observation['ports'] = sorted(set(listeners))
                observation['service_alive'] = process.poll() is None
                for port in listeners:
                    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=1)
                    try:
                        connection.request('GET', '/', headers={'Host': '127.0.0.1', 'Connection': 'close'})
                        observation['request_sent'] = True
                        response = connection.getresponse()
                        body = response.read(4096)
                        observation.update(response_observed=True, status=response.status,
                                           response_headers=dict(response.getheaders()), response_body_preview=body[:512].decode('utf-8', 'replace'),
                                           response_sha256=hashlib.sha256(body).hexdigest(), port=port)
                        break
                    except (OSError, http.client.HTTPException):
                        pass
                    finally:
                        connection.close()
                # Vendor httpd may daemonize: parent exit is not service exit.
                if observation['response_observed']:
                    break
                time.sleep(0.25)
            observation['process_started'] = observation['service_alive'] or observation['response_observed']
            observation['exit_code_before_cleanup'] = process.poll()
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
    observation.update(stdout=read_tail(outpath), stderr=read_tail(errpath))
    return observation


def vm_observations(console):
    """Count output evidence, never echoed argv or mere connection attempts."""
    result = {'kernel_boot_observed': bool(re.search(r'(?m)^FIRMXPLORE_VM_INIT_READY\r?$', console)),
              'vendor_binary_observed': bool(re.search(r'(?m)^FIRMXPLORE_VM_VENDOR_BUSYBOX_OK\r?$', console)),
              'http_responses': [], 'original_vendor_boot': False, 'reconstructed_boot': True}
    for label, url in [('HTTP', 'http://127.0.0.1/'), ('HTTP_LAN', 'http://192.168.0.1/'),
                       ('HTTP_UPNP', 'http://127.0.0.1:1900/')]:
        segment = re.search(r'(?ms)^FIRMXPLORE_VM_' + label + r'_BEGIN\r?$\n(.*?)^FIRMXPLORE_VM_' + label + r'_END\r?$', console)
        if not segment:
            continue
        response = re.search(r'(?m)^\s*HTTP/1\.[01] ([1-5][0-9][0-9])[^\r\n]*', segment[1])
        if response:
            result['http_responses'].append({'url': url, 'status': int(response[1]),
                                               'response_observed': True, 'request_sent': True,
                                               'transcript': segment[1][-2500:]})
    result['response_observed'] = bool(result['http_responses'])
    result['httpd_process_observed'] = bool(re.search(r'(?m)^\s*\d+\s+\S+\s+\S+\s+/usr/bin/httpd(?:[ \t]+[^\r\n]*)?\r?$', console))
    return result


def write_initramfs(root, target, compat_devices=()):
    """Write newc data without ever creating a device on the container host."""
    with gzip.open(target, 'wb', compresslevel=1) as archive:
        inode = 1
        def entry(name, mode, data=b'', major=0, minor=0):
            nonlocal inode
            encoded = name.encode() + b'\0'
            fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, major, minor, len(encoded), 0]
            archive.write(b'070701' + b''.join(f'{x:08x}'.encode() for x in fields))
            archive.write(encoded)
            archive.write(b'\0' * (-(110 + len(encoded)) % 4))
            archive.write(data)
            archive.write(b'\0' * (-len(data) % 4))
            inode += 1
        for base, dirs, files in os.walk(root, followlinks=False):
            parent = Path(base)
            for name in dirs + files:
                path = parent/name
                relative = path.relative_to(root).as_posix()
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    entry(relative, stat.S_IFLNK | 0o777, os.readlink(path).encode())
                elif stat.S_ISDIR(info.st_mode):
                    entry(relative, stat.S_IFDIR | 0o755)
                elif stat.S_ISREG(info.st_mode):
                    entry(relative, stat.S_IFREG | (info.st_mode & 0o777), path.read_bytes())
        entry('dev/console', stat.S_IFCHR | 0o600, major=5, minor=1)
        entry('dev/null', stat.S_IFCHR | 0o666, major=1, minor=3)
        entry('dev/urandom', stat.S_IFCHR | 0o666, major=1, minor=9)
        for name, major, minor in compat_devices:
            entry(name, stat.S_IFCHR | 0o666, major=major, minor=minor)
        entry('TRAILER!!!', 0)


def run_vm(root, endian, *, functional=False):
    import shutil
    bb = '/firmxplore/busybox'
    helper = Path('/opt/FirmAE/binaries')/('busybox.mipsel' if endian == 'little' else 'busybox.mipseb')
    (root/'firmxplore').mkdir(exist_ok=True)
    shutil.copyfile(helper, root/'firmxplore/busybox')
    (root/'firmxplore/busybox').chmod(0o755)
    library = Path('/opt/FirmAE/binaries')/('libnvram.so.mipsel' if endian == 'little' else 'libnvram.so.mipseb')
    (root/'firmadyne').mkdir(exist_ok=True)
    shutil.copyfile(library, root/'firmadyne/libnvram.so')
    sender = Path('/opt/fwagent/http-config-sender.mipsel')
    config_replay = endian == 'little' and sender.is_file() and b'http_init_configByMsg' in (root/'usr/bin/httpd').read_bytes()
    if config_replay:
        shutil.copyfile(sender, root/'firmxplore/http-config-sender')
        (root/'firmxplore/http-config-sender').chmod(0o755)
    firewall_repair = False
    for candidate in ('usr/bin/iptables', 'sbin/iptables'):
        program = root/candidate
        if not program.is_file():
            continue
        original = root/'firmxplore/firewall/iptables'
        original.parent.mkdir(exist_ok=True)
        shutil.copyfile(program, original)
        original.chmod(0o755)
        program.unlink()
        program.write_text('''#!/firmxplore/busybox sh
PREV=
for ARG in "$@"; do
 if [ "$PREV" = "-t" ] && [ "$ARG" = "nat" ]; then exit 0; fi
 PREV="$ARG"
done
exec /firmxplore/firewall/iptables "$@"
''')
        program.chmod(0o755)
        firewall_repair = True
        break
    script = '''#!/firmxplore/busybox sh
BB=/firmxplore/busybox
$BB mount -t proc proc /proc
$BB mount -t sysfs sysfs /sys
$BB mkdir -p /var/tmp /var/run /var/log /var/lock /var/dev /tmp /dev/pts
$BB ifconfig lo 127.0.0.1 up
$BB brctl addbr br0
$BB ifconfig eth0 up
$BB brctl addif br0 eth0
$BB ifconfig br0 192.168.0.1 up
echo FIRMXPLORE_VM_INIT_READY
/bin/busybox echo FIRMXPLORE_VM_VENDOR_BUSYBOX_OK
if [ -f /etc/passwd.bak ]; then $BB cp /etc/passwd.bak /var/passwd; fi
if [ -x /usr/bin/cos ]; then /usr/bin/cos >/tmp/cos.log 2>&1 & fi
$BB sleep 5
if [ -x /usr/bin/cos ] && [ -x /usr/bin/tmpd ]; then /usr/bin/tmpd >/tmp/tmpd.log 2>&1 & fi
if [ -f /web/oem/model.conf ]; then
 /usr/bin/httpd -r >/tmp/httpd.log 2>&1 &
else
 /usr/bin/httpd >/tmp/httpd.log 2>&1 &
fi
# WR940N's vendor module dispatcher waits up to 0x641 * 50 ms for
# the wireless thread before continuing to its management HTTP setup.
if [ -f /web/oem/model.conf ]; then $BB sleep 95; else $BB sleep 30; fi
if [ -x /usr/bin/cos ]; then
 if [ -x /firmxplore/http-config-sender ]; then /firmxplore/http-config-sender; $BB sleep 1; fi
fi
for IPT in /sbin/iptables /usr/bin/iptables; do
 if [ -x "$IPT" ]; then "$IPT" -F; "$IPT" -P INPUT ACCEPT; "$IPT" -P OUTPUT ACCEPT; break; fi
done
echo FIRMXPLORE_VM_NETWORK
$BB ifconfig
$BB netstat -tln
echo FIRMXPLORE_VM_HTTP_BEGIN
$BB wget -S -T 3 -O /tmp/http-body http://127.0.0.1/ 2>/tmp/http-headers
$BB cat /tmp/http-headers
$BB head -c 512 /tmp/http-body
echo
echo FIRMXPLORE_VM_HTTP_END
echo FIRMXPLORE_VM_HTTP_LAN_BEGIN
$BB wget -S -T 3 -O /tmp/http-body-lan http://192.168.0.1/ 2>/tmp/http-headers-lan
$BB cat /tmp/http-headers-lan
$BB head -c 512 /tmp/http-body-lan
echo
echo FIRMXPLORE_VM_HTTP_LAN_END
echo FIRMXPLORE_VM_HTTP_UPNP_BEGIN
$BB wget -S -T 3 -O /tmp/http-upnp http://127.0.0.1:1900/ 2>/tmp/http-upnp-headers
$BB cat /tmp/http-upnp-headers
$BB head -c 512 /tmp/http-upnp
echo
echo FIRMXPLORE_VM_HTTP_UPNP_END
echo FIRMXPLORE_VM_SERVICE_LOGS
$BB head -c 2000 /tmp/httpd.log
$BB tail -c 2500 /tmp/httpd.log
$BB head -c 2000 /tmp/cos.log
$BB tail -c 2500 /tmp/cos.log
$BB cat /proc/devices
for PD in /proc/[0-9]*; do
 CMD=$($BB cat "$PD/comm" 2>/dev/null)
 case "$CMD" in httpd|cos) echo "FIRMXPLORE_PROCESS $PD $CMD"; $BB cat "$PD/wchan"; $BB cat "$PD/syscall";; esac
done
$BB ps
( $BB sleep 8
 echo FIRMXPLORE_VM_POST_PROBE_PROCESSES
 for PD in /proc/[0-9]*; do
  CMD=$($BB cat "$PD/comm" 2>/dev/null)
  case "$CMD" in httpd|cos) echo "FIRMXPLORE_PROCESS $PD $CMD"; $BB cat "$PD/wchan"; $BB cat "$PD/syscall";; esac
 done
 $BB grep -E 'sendto|msg_send|No such file' /tmp/httpd.log | $BB tail -c 2000
 $BB grep -E '^#Msg: (2 pData|HashMatchFlag|cgi_gdpr request|ini header|getObjData_decrypt|http_rsa_decrypt)' /tmp/httpd.log | $BB tail -c 1000
) &
echo FIRMXPLORE_VM_PROBE_READY
$BB sleep 100
echo FIRMXPLORE_VM_COMPLETE
$BB poweroff -f
'''
    if not functional:
        script = script.replace('echo FIRMXPLORE_VM_PROBE_READY\n$BB sleep 100\n','')
    (root/'init').write_text(script)
    (root/'init').chmod(0o755)
    initrd = Path('/work/rootfs.cpio.gz')
    compat_devices = []
    if b'/dev/ar7100_gpio_chrdev' in (root/'usr/bin/httpd').read_bytes():
        # The generic kernel has no Atheros board driver. Its registered
        # brcmboard/nvram compatibility devices provide bounded no-hardware
        # ioctl behavior; these aliases are an explicit fidelity limitation.
        compat_devices = [('dev/ar7100_gpio_chrdev', 206, 0), ('dev/ar7100_flash_chrdev', 111, 0)]
    write_initramfs(root, initrd, compat_devices)
    kernel = '/opt/FirmAE/binaries/vmlinux.' + ('mipsel.4' if endian == 'little' else 'mipseb.4')
    emulator = '/usr/bin/qemu-system-' + ('mipsel' if endian == 'little' else 'mips')
    network = 'user,id=isolated,restrict=on'
    if functional:
        network += ',net=192.168.0.0/24,host=192.168.0.2,hostfwd=tcp:127.0.0.1:18080-192.168.0.1:80'
    command = [emulator, '-M', 'malta', '-m', '256M', '-nographic', '-nodefaults', '-serial', 'stdio',
               '-monitor', 'none', '-netdev', network, '-device', 'e1000,netdev=isolated', '-kernel', kernel, '-initrd', str(initrd),
               '-append', 'console=ttyS0 rdinit=/init panic=1 mem=256M firmadyne.syscall=0 firmadyne.execute=0 FIRMAE_NVRAM=false']
    def functional_check():
        import importlib.util
        spec = importlib.util.spec_from_file_location('isolated_http_probe', '/http_probe.py')
        probe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(probe)
        observations = probe.run(root)
        if observations.get('error_type'):
            time.sleep(10)
        return observations
    vm = run_guest([], command, 'vm', timeout=250 if functional else 140, env_extra={'QEMU_STRACE': ''}, on_ready=functional_check if functional else None)
    console = Path('/work/vm.stdout').read_text(errors='replace') + vm['stderr']
    vm.update(vm_observations(console))
    vm['console'] = console[-32000:]
    vm['startup_wait_seconds'] = 95 if (root/'web/oem/model.conf').is_file() else 30
    vm['runtime_repairs'] = [{'type': 'guest_lan_bridge', 'address': '192.168.0.1', 'stock_vendor_parity': False},
                             {'type': 'guest_filter_flush', 'policies': ['INPUT ACCEPT', 'OUTPUT ACCEPT'], 'stock_vendor_parity': False},
                             {'type': 'kernel_required_nvram_interposer', 'source': str(library),
                              'sha256': hashlib.sha256(library.read_bytes()).hexdigest(),
                              'stock_vendor_parity': False}]
    vm['runtime_repairs'].extend({'type': 'hardware_device_alias', 'path': n, 'major': a, 'minor': b, 'stock_vendor_parity': False} for n, a, b in compat_devices)
    if firewall_repair:
        vm['runtime_repairs'].append({'type': 'skip_unavailable_guest_nat_table', 'scope': 'NAT initialization only; NAT behavior is not validated', 'stock_vendor_parity': False})
    if config_replay:
        vm['runtime_repairs'].append({'type': 'baseline_http_configuration_message', 'message_type': '0x7ee', 'local_http_port': 80, 'authentication_modified': False, 'stock_vendor_parity': False})
    if (root/'usr/bin/cos').is_file() and (root/'usr/bin/tmpd').is_file():
        vm['runtime_repairs'].append({'type': 'vendor_ipc_dependency', 'program': '/usr/bin/tmpd', 'stock_vendor_parity': False})
    return vm


def main():
    import resource
    import sys
    functional = '--functional' in sys.argv[1:]
    # Extraction permits an individual regular member up to MAX_MEMBER_BYTES.
    # Keep the process file-size limit aligned with that validated archive
    # budget so ordinary firmware binaries above 2 MiB do not fail with EFBIG.
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_MEMBER_BYTES, MAX_MEMBER_BYTES))
    result = {'success': False, 'emulation_scope': 'userspace_service', 'full_system_boot': False,
              'process_started': False, 'request_sent': False, 'response_observed': False,
              'runtime_observation_real': False, 'execution_completed': True}
    result['functional_validation_requested'] = functional
    try:
        result['isolation_checks'] = isolation_check()
        source = Path('/input/rootfs.tar.gz')
        result['rootfs_archive_sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
        root = Path('/work/rootfs')
        result['extraction'] = unpack(source, root)
        for name in ('tmp', 'var', 'var/run', 'var/tmp', 'var/log', 'dev', 'proc', 'sys'):
            ensure_runtime_directory(root, name)
        busybox = root/'bin/busybox'
        data = busybox.read_bytes()[:64]
        if data[:4] != b'\x7fELF' or data[4] != 1 or data[5] not in (1, 2):
            raise ValueError('unsupported BusyBox ELF: expected ELF32')
        endian = 'little' if data[5] == 1 else 'big'
        machine = int.from_bytes(data[18:20], endian)
        emulators = {8: ('qemu-mipsel-static' if endian == 'little' else 'qemu-mips-static'), 40: 'qemu-arm-static'}
        if machine not in emulators:
            raise ValueError('unsupported guest machine')
        emulator = '/usr/bin/' + emulators[machine]
        result.update(architecture='mips' if machine == 8 else 'arm', endianness=endian, emulator=emulator)
        prefix = ['/usr/bin/proot', '-0', '-r', str(root), '-q', emulator, '-w', '/', '-b', '/dev', '-b', '/proc']
        smoke = run_guest([emulator, '-L', str(root)], [str(busybox), 'echo', 'FIRMXPLORE_REAL_GUEST_OK'], 'smoke')
        result['smoke'] = smoke
        started = smoke['exit_code'] == 0 and smoke['stdout'].strip() == 'FIRMXPLORE_REAL_GUEST_OK'
        result.update(success=started, process_started=started, runtime_observation_real=started,
                      binary_smoke='observed' if started else 'failed', isolation_verified=True)
        if started:
            result['guest_uname'] = run_guest([emulator, '-L', str(root)], [str(busybox), 'uname', '-m'], 'uname')
            result['proot_smoke'] = run_guest(prefix, ['/bin/busybox', 'echo', 'FIRMXPLORE_PROOT_OK'], 'proot')
            if (root/'usr/bin/cos').is_file():
                # This vendor's rcS starts cos, which owns the shared-memory
                # configuration store needed by httpd. Run the actual program;
                # do not synthesize a successful configuration-store response.
                result['startup_dependency'] = run_guest(prefix, ['/usr/bin/cos'], 'cos', timeout=3)
            result['httpd'] = run_service(prefix)
            result['request_sent'] = result['httpd']['request_sent']
            result['response_observed'] = result['httpd']['response_observed']
            if not result['response_observed'] and machine == 8:
                result['httpd_trace'] = run_guest(prefix, ['/usr/bin/httpd'], 'httpd-trace', timeout=4)
                # Legacy LinuxThreads / vendor IPC assumptions need a guest
                # kernel rather than host-translated userspace syscalls.
                resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_MEMBER_BYTES, MAX_MEMBER_BYTES))
                vm_root = Path('/work/vm-rootfs')
                unpack(source, vm_root)
                for name in ('proc', 'sys', 'dev', 'tmp'):
                    ensure_runtime_directory(vm_root, name)
                result['vm'] = run_vm(vm_root, endian, functional=functional)
                result['functional_validation'] = result['vm'].get('functional_validation') or {}
                if result['vm']['kernel_boot_observed']:
                    result.update(emulation_scope='reconstructed_linux_vm', kernel_boot_observed=True,
                                  vendor_binary_observed=result['vm']['vendor_binary_observed'],
                                  service_process_observed=result['vm']['httpd_process_observed'])
                if result['vm']['response_observed']:
                    result.update(response_observed=True, request_sent=True,
                                  http_responses=result['vm']['http_responses'])
            result['emulation_level'] = ('functional_management' if result.get('functional_validation',{}).get('functional_passed') else
                                         'http_response' if result['response_observed'] else
                                         'guest_kernel_and_vendor_userspace' if result.get('vendor_binary_observed') else
                                         'userspace_binary')
        else:
            result['errors'] = ['guest BusyBox failed under isolated QEMU']
    except Exception as exc:
        result['errors'] = [f'{type(exc).__name__}: {exc}']
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
