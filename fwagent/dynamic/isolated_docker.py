"""Host supervisor for ephemeral, unprivileged Docker/QEMU emulation."""
from __future__ import annotations

from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
import uuid

from fwagent.dynamic import isolated_worker
from fwagent.runtime.command import CommandRunner
from fwagent.tools.common import is_regular_file, sha256_file


# A positive syscall allowlist; namespace/mount/module/kernel-control calls
# intentionally have no entry. ptrace is needed by the PRoot tracer, contained
# in a private PID namespace with no capabilities and an unprivileged uid.
SYSCALLS = '''read write close fstat newfstatat stat lstat statx open openat access faccessat faccessat2
lseek pread64 pwrite64 readv writev preadv pwritev getdents getdents64 readlink readlinkat
mmap mprotect munmap mremap madvise brk msync mincore arch_prctl
rt_sigaction rt_sigprocmask rt_sigreturn rt_sigsuspend rt_sigtimedwait sigaltstack
futex futex_waitv set_robust_list get_robust_list rseq set_tid_address
clock_gettime clock_getres clock_nanosleep nanosleep gettimeofday time times
getpid getppid gettid getuid geteuid getgid getegid getresuid getresgid getgroups
setuid setgid setreuid setregid setresuid setresgid setgroups umask
prlimit64 getrlimit setrlimit getrusage sysinfo uname getrandom
dup dup2 dup3 fcntl ioctl pipe pipe2 poll ppoll select pselect6
clone clone3 fork vfork execve execveat wait4 waitid exit exit_group
kill tkill tgkill setsid getsid setpgid getpgid getpgrp
ptrace process_vm_readv process_vm_writev prctl sched_yield sched_getaffinity sched_setaffinity
sched_get_priority_min sched_get_priority_max sched_getparam sched_setparam sched_getscheduler sched_setscheduler
io_setup io_destroy io_submit io_cancel io_getevents io_pgetevents timerfd_create timerfd_settime timerfd_gettime
socket socketpair connect bind listen accept accept4 getsockname getpeername
sendto recvfrom sendmsg recvmsg sendmmsg recvmmsg shutdown setsockopt getsockopt
epoll_create epoll_create1 epoll_ctl epoll_wait epoll_pwait eventfd eventfd2
mkdir mkdirat rmdir unlink unlinkat rename renameat renameat2 link linkat symlink symlinkat
chmod fchmod fchmodat chown fchown lchown fchownat truncate ftruncate utime utimes utimensat
chdir fchdir getcwd fsync fdatasync sync statfs fstatfs
getxattr lgetxattr fgetxattr listxattr llistxattr flistxattr memfd_create
semget semop semctl semtimedop shmget shmat shmdt shmctl msgget msgsnd msgrcv msgctl ipc
fcntl64 fstat64 stat64 lstat64 statfs64 fstatfs64 llseek _llseek mmap2
getuid32 geteuid32 getgid32 getegid32 getresuid32 getresgid32 getgroups32
setuid32 setgid32 setresuid32 setresgid32 setgroups32 ugetrlimit
'''.split()


def seccomp_profile():
    return {'defaultAction': 'SCMP_ACT_ERRNO', 'defaultErrnoRet': 1,
            'architectures': ['SCMP_ARCH_X86_64', 'SCMP_ARCH_X86', 'SCMP_ARCH_X32'],
            'syscalls': [{'names': sorted(set(SYSCALLS) - {'clone', 'clone3'}), 'action': 'SCMP_ACT_ALLOW'},
                         {'names': ['clone'], 'action': 'SCMP_ACT_ALLOW',
                          'args': [{'index': 0, 'value': 0x7e020000, 'valueTwo': 0, 'op': 'SCMP_CMP_MASKED_EQ'}]},
                         {'names': ['clone3'], 'action': 'SCMP_ACT_ERRNO', 'errnoRet': 38}]}


class IsolatedDockerBackend:
    name = 'isolated-qemu'

    def __init__(self, workspace, runner=None, image='firmxplore-isolated:latest'):
        self.task_dir = Path(workspace).resolve()
        self.output = self.task_dir/'dynamic/isolated'
        self.output.mkdir(parents=True, exist_ok=True)
        self.runner = runner or CommandRunner(self.output/'logs')
        self.image = image

    def _archive(self):
        path = self.task_dir/'canonical-rootfs.tar.gz'
        if not is_regular_file(path) or path.is_symlink() or path.stat().st_size > 64*1024*1024:
            raise ValueError('a regular canonical-rootfs.tar.gz (at most 64 MiB) is required inside the task directory')
        return path

    def prepare(self, firmware_path=None):
        try:
            path = self._archive()
            return {'success': True, 'rootfs_archive': str(path), 'sha256': sha256_file(path)}
        except (OSError, ValueError) as exc:
            return {'success': False, 'errors': [str(exc)]}

    def check_environment(self):
        result = self.runner.run(['docker', 'image', 'inspect', self.image, '--format', '{{.Id}}'], timeout=15)
        return {'success': result.exit_code == 0, 'image': self.image, 'image_id': result.stdout.strip(), 'errors': [] if result.exit_code == 0 else [result.stderr]}

    def boot(self, firmware_path=None, *, timeout=180):
        timeout = max(20, min(180, int(timeout)))
        name = 'firmxplore-isolated-' + uuid.uuid4().hex
        result = {'success': False, 'backend': self.name, 'emulation_scope': 'userspace_service',
                  'full_system_boot': False, 'process_started': False, 'runtime_observation_real': False,
                  'execution_completed': True, 'container': name}
        created = False
        cleaned = False
        def cleanup_worker():
            nonlocal cleaned
            if cleaned:
                return
            cleanup = self.runner.run(['docker', 'rm', '-f', name], timeout=15) if created else None
            result['cleanup_succeeded'] = (cleanup is None or cleanup.exit_code == 0
                                            or 'No such container' in cleanup.stderr)
            cleaned = True
            if not result['cleanup_succeeded']:
                result.update(success=False, errors=[*(result.get('errors') or []), 'worker cleanup failed'])
        try:
            archive = self._archive()
            environment = self.check_environment()
            if not environment['success']:
                raise RuntimeError('Docker worker image unavailable: ' + str(environment['errors']))
            with ExitStack() as stack:
                scratch = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='isolated-', dir=self.output)))
                stack.callback(cleanup_worker)
                snapshot = scratch/'rootfs.tar.gz'
                # Own a stable bounded snapshot rather than mounting an untrusted
                # pathname that could be swapped after validation.
                from fwagent.tools.common import open_regular_file
                with open_regular_file(archive) as source, snapshot.open('xb') as dest:
                    count = 0
                    while chunk := source.read(65536):
                        count += len(chunk)
                        if count > 64*1024*1024:
                            raise ValueError('rootfs input quota exceeded')
                        dest.write(chunk)
                digest = sha256_file(snapshot)
                worker_snapshot = scratch/'worker.py'
                worker_bytes = Path(isolated_worker.__file__).read_bytes()
                worker_snapshot.write_bytes(worker_bytes)
                profile = scratch/'seccomp.json'
                profile.write_text(json.dumps(seccomp_profile()), encoding='utf-8')
                command = ['docker', 'create', '--rm', '--name', name, '--network', 'none', '--ipc', 'none',
                           '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                           '--security-opt', 'seccomp=' + str(profile), '--user', '65534:65534',
                           '--memory', '512m', '--memory-swap', '512m', '--cpus', '2', '--pids-limit', '128',
                           '--ulimit', 'nofile=512:512', '--stop-timeout', '3',
                           '--log-opt', 'max-size=4m', '--log-opt', 'max-file=1',
                           '--tmpfs', '/work:rw,exec,nosuid,nodev,size=256m,mode=700,uid=65534,gid=65534',
                           '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=32m,mode=1777',
                           '--mount', f'type=bind,source={snapshot},target=/input/rootfs.tar.gz,readonly',
                           '--mount', f'type=bind,source={worker_snapshot},target=/worker.py,readonly',
                           '--workdir', '/work', '--entrypoint', '/usr/bin/timeout', environment['image_id'],
                           '-k', '3', str(timeout), 'python', '-I', '-B', '/worker.py']
                # The daemon can create a container even if the client loses its
                # response. Cleanup always addresses our generated unique name.
                created = True
                create = self.runner.run(command, timeout=20)
                if create.exit_code != 0:
                    raise RuntimeError('worker creation failed: ' + create.stderr)
                inspect = self.runner.run(['docker', 'inspect', name], timeout=15)
                settings = json.loads(inspect.stdout)[0]
                host = settings['HostConfig']
                if not (host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] and not host['Privileged']
                        and host['CapDrop'] == ['ALL'] and not host.get('CapAdd')
                        and host.get('PidMode', '') != 'host' and host.get('IpcMode') == 'none'
                        and host.get('AutoRemove') is True and settings['Config']['User'] == '65534:65534'
                        and host['Memory'] == 512*1024*1024
                        and not host.get('Devices') and not host.get('PortBindings')
                        and all(not mount['RW'] for mount in settings.get('Mounts', []) if mount['Type'] == 'bind')):
                    raise RuntimeError('daemon isolation settings verification failed')
                result.update(image_id=environment['image_id'], isolation_settings_verified=True, input_sha256=digest,
                              worker_sha256=sha256_file(worker_snapshot), seccomp_sha256=sha256_file(profile))
                execution = self.runner.run(['docker', 'start', '-a', name], timeout=timeout+15)
                if execution.timed_out or execution.exit_code != 0:
                    raise RuntimeError('worker failed or timed out: ' + execution.stderr[-2000:])
                payload = json.loads(execution.stdout)
                if not isinstance(payload, dict) or type(payload.get('success')) is not bool:
                    raise ValueError('invalid isolated-worker result schema')
                if payload.get('rootfs_archive_sha256') != digest:
                    raise RuntimeError('worker input identity mismatch')
                result.update(payload)
                result['backend'] = self.name
        except (OSError, ValueError, RuntimeError, KeyError, IndexError) as exc:
            result.update(success=False, errors=[f'{type(exc).__name__}: {exc}'])
        finally:
            cleanup_worker()
            (self.output/'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
            observed = bool(result.get('success') and result.get('response_observed'))
            summary = {key: result.get(key) for key in (
                'backend', 'emulation_scope', 'emulation_level', 'full_system_boot',
                'kernel_boot_observed', 'vendor_binary_observed', 'process_started',
                'request_sent', 'response_observed', 'cleanup_succeeded')}
            summary.update(runtime_backend=self.name, endpoint_established=observed,
                           dynamic_status='service_response_observed' if observed else 'emulated_no_response' if result.get('success') else 'runtime_failed',
                           http_responses=result.get('http_responses', []),
                           runtime_repairs=result.get('vm', {}).get('runtime_repairs', []),
                           evidence_path='dynamic/isolated/result.json')
            (self.output.parent/'runtime_summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
        return result

    def stop(self):
        return {'success': True, 'stopped': True, 'ephemeral': True}

    def status(self):
        return {'status': 'stopped', 'backend': self.name, 'ephemeral': True}

    def logs(self, limit=200):
        path = self.output/'result.json'
        return path.read_text(encoding='utf-8').splitlines()[-limit:] if path.exists() else []
