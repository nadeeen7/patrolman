"""Resolve native executables or Ruby/Perl scripts without a command shell."""
import os
import shutil
import sys
import tempfile
from pathlib import Path
WINDOWS = os.name == 'nt'
PROJECT_ROOT = Path(__file__).resolve().parents[2]
LOCAL_CANDIDATES = {
    'nmap': Path('tools/nmap/nmap.exe'),
    'httpx': Path('tools/httpx/httpx.exe'),
    'whatweb': Path('tools/whatweb/WhatWeb-0.6.4/whatweb'),
    'nuclei': Path('tools/nuclei/nuclei.exe'),
    'gitleaks': Path('tools/gitleaks/gitleaks.exe'),
    'trivy': Path('tools/trivy/trivy.exe'),
    'subfinder': Path('tools/subfinder/subfinder.exe'),
    # sslyze.exe is blocked by Windows Application Control on this host;
    # the adapter declares MODULE_BASED=True so find_argv returns
    # [sys.executable, '-m', 'sslyze'] instead.
    'wapiti': Path('.venv/Scripts/wapiti.exe'),
}


def _runtime_candidates(name):
    """Return narrow, conventional Windows runtime locations; never crawl a drive."""
    if not WINDOWS:
        return ()
    local = Path(os.getenv('LOCALAPPDATA', ''))
    program_files = Path(os.getenv('ProgramFiles', r'C:\Program Files'))
    if name == 'ruby':
        candidates = [Path(r'C:\Ruby34-x64\bin\ruby.exe')]
        candidates.extend(Path(path) for path in (
            list(Path('C:/').glob('Ruby*')) +
            list(program_files.glob('Ruby*'))
        ) if path.is_dir())
        return tuple(path / 'bin' / 'ruby.exe' for path in candidates if path.is_dir())
    return ()


def find_runtime(name):
    """Find a supported native script runtime without relaxing executable policy."""
    located = shutil.which(name)
    if located:
        return located
    for candidate in _runtime_candidates(name):
        if candidate.is_file():
            return str(candidate.resolve())
    return None


def _known_candidates(commands):
    name = Path(commands[0]).stem.lower()
    relative = LOCAL_CANDIDATES.get(name)
    if relative is not None:
        candidate = PROJECT_ROOT / relative
        if candidate.is_file():
            yield candidate
    if not WINDOWS:
        return
    program_files = Path(os.getenv('ProgramFiles', r'C:\Program Files'))
    program_files_x86 = Path(os.getenv('ProgramFiles(x86)', r'C:\Program Files (x86)'))
    if name == 'nmap':
        yield program_files_x86 / 'Nmap' / 'nmap.exe'
        yield program_files / 'Nmap' / 'nmap.exe'


def path_variable(commands):
    """Return the documented AVA path override for an adapter command tuple."""
    return 'AVA_' + Path(commands[0]).stem.upper() + '_PATH'


def local_candidate(commands):
    """Find a bundled Windows candidate for status reporting, never implicit execution."""
    if not WINDOWS:
        return None
    relative = LOCAL_CANDIDATES.get(Path(commands[0]).stem.lower())
    if relative is None:
        return None
    candidate = PROJECT_ROOT / relative
    return candidate.resolve() if candidate.is_file() else None


def _first_line(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as handle:
            return handle.readline(512).strip().lower()
    except OSError: return ''


def resolve(argv):
    if not argv: return None
    path = argv[0]
    extension = Path(path).suffix.lower()
    if extension in {'.bat', '.cmd', '.ps1', '.sh'}: return None
    if not WINDOWS: return argv
    if extension in {'.exe', '.com'}: return argv
    line = _first_line(path)
    interpreter = 'ruby' if 'ruby' in line or extension == '.rb' else 'perl' if 'perl' in line or extension == '.pl' else None
    if not interpreter: return None
    runtime = find_runtime(interpreter)
    return [runtime, path, *argv[1:]] if runtime else None


def _venv_python_executable():
    """Return the path to the project's virtual-environment Python interpreter.

    Per safety requirement:
    - Use the project's existing virtual-environment interpreter for module-based execution.
    - Never invoke a global Python interpreter as a fallback.
    """
    if sys.prefix != sys.base_prefix:
        return sys.executable
    venv_dir = PROJECT_ROOT / '.venv'
    venv_py = (venv_dir / 'Scripts' / 'python.exe') if WINDOWS else (venv_dir / 'bin' / 'python')
    if venv_py.is_file():
        return str(venv_py.resolve())
    return None


def _module_argv(commands):
    """Return [sys.executable, '-m', module_name] for MODULE_BASED adapters.

    This is the approved fallback when the adapter's console-script .exe is
    blocked by Windows Application Control. The venv Python interpreter that
    is already running the backend is always an approved binary, and
    ``-m module_name`` invokes SSLyze (or any other MODULE_BASED package)
    without touching the policy-blocked wrapper script.

    Returns None if the module is not importable in the current environment,
    so callers can still report a clean 'missing' status.
    """
    try:
        from ..integrations import ADAPTERS
    except ImportError:
        return None
    name = Path(commands[0]).stem.lower()
    adapter = ADAPTERS.get(name)
    if adapter is None or not getattr(adapter, 'MODULE_BASED', False):
        return None
    module_name = getattr(adapter, 'MODULE_NAME', name)

    python_exe = _venv_python_executable()
    if not python_exe:
        return None

    if sys.prefix == sys.base_prefix:
        venv_sp = PROJECT_ROOT / '.venv' / 'Lib' / 'site-packages'
        if venv_sp.is_dir() and str(venv_sp) not in sys.path:
            sys.path.insert(0, str(venv_sp))

    try:
        import importlib
        importlib.import_module(module_name)
    except ImportError:
        return None

    return [python_exe, '-m', module_name]


def find_argv(commands):
    # MODULE_BASED adapters (e.g. SSLyze) must always invoke via
    # [python, -m, module_name] unless the operator supplies an explicit path
    # override. Without this check, shutil.which() could find the blocked
    # console-script .exe before the module fallback is tried, which would
    # produce a command that succeeds in resolution but fails at execution due
    # to Windows Application Control policy.
    override = os.getenv(path_variable(commands))
    if not override:
        module_argv = _module_argv(commands)
        if module_argv:
            return module_argv
    candidates = (override,) if override else (*_known_candidates(commands), *commands)
    for command in candidates:
        try:
            path = Path(command)
            if not path.is_absolute():
                project_relative = PROJECT_ROOT / path
                if project_relative.is_file():
                    path = project_relative
            if path.is_file():
                located = str(path.resolve())
            else:
                located = shutil.which(command)
                if not located:
                    scripts_dir = Path(sys.prefix) / ('Scripts' if WINDOWS else 'bin')
                    located = shutil.which(command, path=str(scripts_dir))
        except (OSError, ValueError): located = None
        if not located: continue
        resolved = resolve([located])
        if resolved: return resolved[0] if len(resolved) == 1 else resolved
    return None


def configure_tool_environment():
    """Populate startup-time paths for discovered local tools, preserving overrides."""
    global _TRIVY_CACHE
    for runtime in ('ruby',):
        executable = find_runtime(runtime)
        if executable:
            directory = str(Path(executable).parent)
            entries = os.environ.get('PATH', '').split(os.pathsep)
            if directory not in entries:
                os.environ['PATH'] = directory + (os.pathsep + os.environ['PATH'] if os.environ.get('PATH') else '')

    from ..integrations import ADAPTERS
    for module in ADAPTERS.values():
        variable = path_variable(module.COMMANDS)
        if variable in os.environ:
            continue
        # MODULE_BASED adapters (e.g. SSLyze) always derive their invocation
        # from sys.executable at runtime via _module_argv().  Storing a plain
        # module-name string as an AVA_*_PATH variable would bypass that logic
        # and cause the native-path resolver to pick up the blocked .exe again.
        if getattr(module, 'MODULE_BASED', False):
            continue
        executable = find_argv(module.COMMANDS)
        if not executable:
            continue
        if isinstance(executable, (list, tuple)):
            artifact = executable[-1] if len(executable) >= 3 and executable[-2] == '-jar' else executable[-1]
        else:
            artifact = executable
        os.environ[variable] = str(artifact)

    if 'AVA_TRIVY_CACHE_DIR' not in os.environ:
        from ..integrations.trivy import discover_cache
        database_cache = discover_cache()
        if database_cache:
            os.environ['AVA_TRIVY_CACHE_DIR'] = str(database_cache)
        else:
            if 'AVA_TRIVY_SCANNERS' not in os.environ:
                os.environ['AVA_TRIVY_SCANNERS'] = 'misconfig,secret'
            _TRIVY_CACHE = tempfile.TemporaryDirectory(prefix='patrolman-trivy-cache-')
            os.environ['AVA_TRIVY_CACHE_DIR'] = _TRIVY_CACHE.name


_TRIVY_CACHE = None


def find(commands):
    result = find_argv(commands)
    return [result] if isinstance(result, str) else result
