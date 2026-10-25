"""Subprocess execution with hard output/time bounds and whole-tree cleanup.

Scanner binaries are external programs, so the runner must work on both POSIX
process groups and native Windows process trees. Output is drained by reader
threads rather than a selector because the Windows default selector cannot
watch anonymous pipes.

Windows has no process-group equivalent: a job object is what makes the POSIX
"kill the whole session" guarantee hold, including descendants that outlive the
process we launched.
"""
import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass

POSIX = os.name == 'posix'
WINDOWS = os.name == 'nt'
KILL_TIMEOUT = 10
DRAIN_GRACE = 2.0
READ_SIZE = 65536
POLL_INTERVAL = .05
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
# Confirmed Windows policy-block evidence, and nothing weaker. 577
# (ERROR_INVALID_IMAGE_HASH) and 1260 (ERROR_ACCESS_DISABLED_BY_POLICY) are
# the codes Windows itself raises when Application Control / Code Integrity /
# group policy refuses a file. The marker tuples are the exact system message
# texts those policies print to stderr (577/1260 system text; the 4551
# "An Application Control policy has blocked this file" wording observed live
# on this host from Python and Ruby). Access-denied, bad-image, missing-DLL,
# antivirus (225/226) and ordinary non-zero exits are deliberately *not*
# confirmed blocks: they surface as EXECUTION_BLOCKED/UNKNOWN upstream.
POLICY_WINERRORS = frozenset({577, 1260})
POLICY_OUTPUT_MARKERS = (
    'an application control policy has blocked',
    'cannot verify the digital signature',
    'blocked by group policy',
)


@dataclass
class ProcessResult:
    state: str
    stdout: str = ''
    stderr: str = ''
    exit_code: int | None = None
    winerror: int | None = None


def policy_block_evidence(result):
    """Confirmed Windows policy-block evidence for a failed run, else None.

    Two forms count: the OS error code raised at launch (577/1260), or an
    exact system message printed to stderr by a process that did not complete.
    Stdout is deliberately ignored so scanned content can never manufacture a
    verdict, and a successful run is never reinterpreted as a block.
    """
    if result.state in {'completed', 'cancelled'}:
        return None
    if result.state == 'blocked' or result.winerror in POLICY_WINERRORS:
        return result.stderr or f'Windows reported policy error {result.winerror}.'
    marker = next((m for m in POLICY_OUTPUT_MARKERS if m in (result.stderr or '').lower()), None)
    if marker:
        return f'Windows policy message in stderr: "{marker}".'
    return None


def _job_structures():
    """ctypes layout for JOBOBJECT_EXTENDED_LIMIT_INFORMATION."""
    import ctypes

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in
                    ('ReadOperationCount', 'WriteOperationCount', 'OtherOperationCount',
                     'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')]

    class BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [('PerProcessUserTimeLimit', ctypes.c_longlong),
                    ('PerJobUserTimeLimit', ctypes.c_longlong),
                    ('LimitFlags', ctypes.c_uint32),
                    ('MinimumWorkingSetSize', ctypes.c_size_t),
                    ('MaximumWorkingSetSize', ctypes.c_size_t),
                    ('ActiveProcessLimit', ctypes.c_uint32),
                    ('Affinity', ctypes.c_size_t),
                    ('PriorityClass', ctypes.c_uint32),
                    ('SchedulingClass', ctypes.c_uint32)]

    class EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [('BasicLimitInformation', BASIC_LIMIT_INFORMATION),
                    ('IoInfo', IO_COUNTERS),
                    ('ProcessMemoryLimit', ctypes.c_size_t),
                    ('JobMemoryLimit', ctypes.c_size_t),
                    ('PeakProcessMemoryUsed', ctypes.c_size_t),
                    ('PeakJobMemoryUsed', ctypes.c_size_t)]

    return EXTENDED_LIMIT_INFORMATION


class _Job:
    """Windows job object; the analogue of a POSIX process group."""

    def __init__(self):
        self.handle = None
        try:
            import ctypes
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel32.CreateJobObjectW.restype = ctypes.c_void_p
            kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
            kernel32.SetInformationJobObject.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                                         ctypes.c_void_p, ctypes.c_uint32]
            kernel32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            kernel32.TerminateJobObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            self._ctypes, self._kernel32 = ctypes, kernel32
            handle = kernel32.CreateJobObjectW(None, None)
            if not handle:
                return
            limits = _job_structures()()
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not kernel32.SetInformationJobObject(handle, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                                                    ctypes.byref(limits), ctypes.sizeof(limits)):
                kernel32.CloseHandle(handle)
                return
            self.handle = handle
        except (OSError, AttributeError, ValueError):
            self.handle = None

    def assign(self, process):
        """Bind a freshly launched process so its descendants share this job."""
        if not self.handle:
            return False
        try:
            return bool(self._kernel32.AssignProcessToJobObject(self.handle, self._ctypes.c_void_p(int(process._handle))))
        except (OSError, AttributeError, ValueError):
            return False

    def terminate(self):
        if self.handle:
            self._kernel32.TerminateJobObject(self.handle, 1)

    def close(self):
        # KILL_ON_JOB_CLOSE makes this the last line of defence for descendants.
        if self.handle:
            self._kernel32.CloseHandle(self.handle)
            self.handle = None


class _Capture:
    """One shared stdout+stderr budget, matching the single capture limit."""

    def __init__(self, budget):
        self.budget = budget
        self.buffers = {'stdout': bytearray(), 'stderr': bytearray()}
        self.lock = threading.Lock()
        self.exceeded = False

    def add(self, name, chunk):
        """Store what fits; return False once the bound is reached."""
        with self.lock:
            room = self.budget - len(self.buffers['stdout']) - len(self.buffers['stderr'])
            if room > 0:
                self.buffers[name].extend(chunk[:room])
            if room <= 0 or len(chunk) > room:
                self.exceeded = True
                return False
            return True

    def text(self, name):
        with self.lock:
            return bytes(self.buffers[name]).decode('utf-8', 'replace')


def _launch_options():
    if POSIX:
        return {'start_new_session': True}
    return {'creationflags': getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0) |
                            getattr(subprocess, 'CREATE_NO_WINDOW', 0) | 0x00000004}


def _kill_group(process):
    """POSIX: signal the whole group, including members alive after the leader exits."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False


def _kill_tree(process):
    """Windows fallback: taskkill walks the tree, but only while its root runs."""
    if process.poll() is not None:
        return False
    try:
        subprocess.run(['taskkill', '/F', '/T', '/PID', str(process.pid)], stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=KILL_TIMEOUT)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def _terminate(process, job):
    if POSIX:
        _kill_group(process)
    elif job:
        job.terminate()
    elif not _kill_tree(process):
        try:
            process.kill()
        except OSError:
            pass


def _drain(stream, name, capture):
    """Read incrementally; buffered read(n) would block until EOF."""
    descriptor = stream.fileno()
    try:
        while True:
            chunk = os.read(descriptor, READ_SIZE)
            if not chunk:
                break
            if not capture.add(name, chunk):
                break
    except (OSError, ValueError):
        pass


def run(argv, *, timeout=90, max_output=2_000_000, cancel=None, cwd=None, output_files=()):
    if not POSIX and not WINDOWS:
        return ProcessResult('failed', stderr='Scanner execution is unsupported on this platform.')
    if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and '\0' not in x for x in argv):
        raise ValueError('Expected a fixed argv list.')
    if timeout <= 0 or max_output <= 0:
        raise ValueError('Bounds must be positive.')
    if cancel and cancel.is_set():
        return ProcessResult('cancelled')
    # Do not pass API tokens, cloud credentials, proxy settings or user configs.
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LANG': 'C.UTF-8',
           'GOMAXPROCS': '2', 'HOME': str(cwd or '/nonexistent'), 'XDG_CONFIG_HOME': str(cwd or '/nonexistent')}
    if WINDOWS:
        # Windows tooling needs its system root and executable extensions to load
        # its own libraries. These carry no credentials.
        env['SystemRoot'] = os.environ.get('SystemRoot', r'C:\Windows')
        env['PATHEXT'] = os.environ.get('PATHEXT', '.COM;.EXE')
        # POSIX children get LANG=C.UTF-8 above; Python-based console tools
        # (wapiti.exe, sslyze.exe) otherwise fall back to the host ANSI
        # codepage for piped output, and Wapiti's randomly chosen banner
        # contains characters cp1252 cannot encode, crashing the child with a
        # UnicodeEncodeError before it starts. UTF-8 mode fixes that; the
        # variable carries no credential or host locale setting.
        env['PYTHONUTF8'] = '1'
        env['PYTHONIOENCODING'] = 'utf-8'
        env['USERPROFILE'] = str(cwd or os.getcwd())
        env['APPDATA'] = str(cwd or os.getcwd())
        env['LOCALAPPDATA'] = str(cwd or os.getcwd())
        env['TEMP'] = str(cwd or os.getcwd())
        env['TMP'] = str(cwd or os.getcwd())
    job = _Job() if WINDOWS else None
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=False, env=env, cwd=cwd,
                                   **_launch_options())
    except FileNotFoundError:
        if job: job.close()
        return ProcessResult('unavailable', stderr='Executable not found.')
    except OSError as exc:
        if job: job.close()
        winerror = getattr(exc, 'winerror', None)
        exc_str = str(exc).lower()
        if winerror in POLICY_WINERRORS or any(m in exc_str for m in POLICY_OUTPUT_MARKERS):
            return ProcessResult('blocked', stderr='Windows policy prevented execution; ask the policy administrator to approve the official binary.', winerror=winerror)
        # A launch refusal Windows did not attribute to policy. Report only the
        # error number: the OSError text would carry the executable path.
        message = (f'Windows refused to launch the executable (error {winerror}); evidence is insufficient to confirm a policy block.'
                   if winerror is not None else 'Unable to launch executable.')
        return ProcessResult('failed', stderr=message, winerror=winerror)
    if WINDOWS:
        # Launch suspended: no descendant can escape before assignment.
        if not job or not job.assign(process):
            process.kill(); process.wait(timeout=KILL_TIMEOUT)
            if job: job.close()
            process.stdout.close(); process.stderr.close()
            return ProcessResult('failed', stderr='Windows process containment could not be established.')
        try:
            import ctypes
            resume = ctypes.WinDLL('ntdll').NtResumeProcess
            resume.argtypes = [ctypes.c_void_p]
            resume.restype = ctypes.c_long
            if resume(ctypes.c_void_p(int(process._handle))) != 0:
                raise OSError('Could not resume contained process')
        except (OSError, AttributeError):
            job.terminate(); process.wait(timeout=KILL_TIMEOUT); job.close()
            process.stdout.close(); process.stderr.close()
            return ProcessResult('failed', stderr='Unable to start contained Windows process.')
    capture = _Capture(max_output)
    readers = [threading.Thread(target=_drain, args=(process.stdout, 'stdout', capture), daemon=True),
               threading.Thread(target=_drain, args=(process.stderr, 'stderr', capture), daemon=True)]
    for reader in readers:
        reader.start()
    state = 'completed'
    started = time.monotonic()
    drain_deadline = None
    try:
        while True:
            if any(path.exists() and path.stat().st_size > max_output for path in output_files):
                state = 'output_limit'; break
            if cancel and cancel.is_set():
                state = 'cancelled'; break
            if capture.exceeded:
                state = 'output_limit'; break
            if process.poll() is None:
                if time.monotonic() - started >= timeout:
                    state = 'timed_out'; break
            elif not any(reader.is_alive() for reader in readers):
                break
            else:
                # The executable already finished inside the bound, so leftover
                # readers only mean a descendant inherited the capture pipes.
                # Never let that push the total runtime past the timeout.
                drain_deadline = drain_deadline or time.monotonic() + min(DRAIN_GRACE, timeout)
                if time.monotonic() >= drain_deadline:
                    break
            time.sleep(POLL_INTERVAL)
    finally:
        # Also clean up descendants after the main process exits.
        _terminate(process, job)
        try:
            process.wait(timeout=KILL_TIMEOUT)
        except subprocess.TimeoutExpired:
            pass
        for reader in readers:
            reader.join(timeout=KILL_TIMEOUT)
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except OSError:
                pass
        if job:
            job.close()
    if state == 'completed' and (capture.exceeded or any(path.exists() and path.stat().st_size > max_output for path in output_files)):
        state = 'output_limit'
    if state == 'completed' and process.returncode != 0:
        state = 'failed'
    return ProcessResult(state, capture.text('stdout'), capture.text('stderr'), process.returncode)
