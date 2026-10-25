"""Single-process loopback server; lock prevents duplicate queue owners."""
import os
import socket
import sys

# Disable compiled Cython C-extensions in SQLAlchemy to ensure compatibility
# with Windows Defender Application Control (WDAC) and AppLocker policies.
os.environ.setdefault('DISABLE_SQLALCHEMY_CEXT', '1')
from .config import Settings
from werkzeug.serving import make_server

HOST = '127.0.0.1'


def port_available(host, port):
    """Report whether a loopback port can be bound for exclusive listening.

    Windows SO_REUSEADDR lets a second server bind a port another program is
    already serving, so the backend would start and then answer nothing. The
    exclusive flag turns that silent hijack into a clear startup failure.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            probe.bind((host, port))
        except OSError:
            return False
        return True
    finally:
        probe.close()


def lock_data_directory(directory):
    """Advisory exclusive lock on the data directory, held for the process lifetime.

    Returns the open descriptor, or None when another backend already owns the
    directory. POSIX uses flock; Windows uses a one-byte msvcrt region lock,
    which the operating system releases when the process exits.
    """
    descriptor = os.open(directory / 'server.lock', os.O_RDWR | os.O_CREAT)
    if os.name == 'posix':
        import fcntl
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(descriptor)
            return None
        return descriptor
    import msvcrt
    try:
        msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
    except OSError:
        os.close(descriptor)
        return None
    return descriptor


def main():
    from .app import create_app
    from .services.executables import configure_tool_environment
    from .env_file import load as load_env_file
    load_env_file()
    configure_tool_environment()
    settings = Settings.from_env()
    settings.validate()
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    if not port_available(HOST, settings.port):
        raise SystemExit(f'Port {settings.port} is already in use by another program. '
                         'Stop it or choose a free port with AVA_PORT.')
    lock = lock_data_directory(settings.data_dir)
    if lock is None:
        raise SystemExit('A backend already owns this data directory.')
    app = None
    server = None
    try:
        app = create_app(settings)
        server = make_server(HOST, settings.port, app, threaded=True)
        print(
            '========================================\n'
            'PATROLMAN\n'
            'Automated Vulnerability Assessment Framework\n'
            '========================================\n'
            'Status: RUNNING\n'
            f'Local URL: http://{HOST}:{settings.port}\n'
            f'Port: {settings.port}\n'
            '========================================',
            flush=True,
        )
        server.serve_forever()
    finally:
        if server is not None:
            server.server_close()
        if app is not None:
            app.extensions['scan_manager'].shutdown()
            app.extensions['database'].dispose()
        os.close(lock)


def run():
    """CLI entry point: load the optional project `.env`, then start the server.

    Configuration failures are reported once, without a traceback, so the
    actionable message is not buried under stack frames and the token value is
    never printed. An exported variable always wins over the file, so the
    documented PowerShell and Credential Manager workflows are unaffected.
    """
    from .env_file import load as load_env_file

    summary = load_env_file()
    if summary['error']:
        print(f'PATROLMAN: {summary["error"]}', file=sys.stderr, flush=True)
    elif summary['loaded']:
        print(
            f'PATROLMAN: loaded {summary["loaded"]} AVA_* setting(s) from {summary["path"]}.\n'
            'Values are not displayed. Exported environment variables take precedence.',
            file=sys.stderr, flush=True,
        )
    if summary['rejected']:
        print(
            f'PATROLMAN: ignored {summary["rejected"]} malformed .env line(s); only '
            'AVA_* NAME=value entries without quotes or line breaks are accepted.',
            file=sys.stderr, flush=True,
        )
    try:
        main()
    except ValueError as error:
        raise SystemExit(f'PATROLMAN configuration error: {error}') from None


if __name__ == '__main__':
    run()
