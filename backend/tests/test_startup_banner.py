import pytest

from backend import app as app_module
from backend import server as server_module
from backend.config import Settings

SYNTHETIC_TOKEN = 'synthetic-startup-token-' + 'x' * 32


class FakeServer:
    def __init__(self, events, capsys):
        self.events = events
        self.capsys = capsys

    def serve_forever(self):
        self.events.append(('serving', self.capsys.readouterr().out))

    def server_close(self):
        self.events.append(('closed',))


class FakeApp:
    extensions = {
        'scan_manager': type('Manager', (), {'shutdown': lambda self: None})(),
        'database': type('Database', (), {'dispose': lambda self: None})(),
    }


def test_startup_banner_never_displays_configured_token(
    tmp_path, monkeypatch, capsys
):
    settings = Settings(tmp_path, SYNTHETIC_TOKEN, port=54731)
    events = []
    monkeypatch.setattr(Settings, 'from_env', classmethod(lambda cls: settings))
    monkeypatch.setattr(server_module, 'port_available', lambda host, port: True)
    monkeypatch.setattr(server_module, 'lock_data_directory', lambda directory: 123)
    monkeypatch.setattr(server_module.os, 'close', lambda descriptor: None)
    monkeypatch.setattr('backend.services.executables.configure_tool_environment', lambda: None)
    monkeypatch.setattr(app_module, 'create_app', lambda configured: FakeApp())

    def bind(host, port, app, *, threaded):
        events.append(('ready', host, port, threaded))
        return FakeServer(events, capsys)

    monkeypatch.setattr(server_module, 'make_server', bind)
    server_module.main()

    ready_index = next(i for i, event in enumerate(events) if event[0] == 'ready')
    serving_index = next(i for i, event in enumerate(events) if event[0] == 'serving')
    assert events[ready_index] == ('ready', '127.0.0.1', 54731, True)
    assert ready_index < serving_index
    output = events[serving_index][1]
    assert 'PATROLMAN' in output
    assert 'Status: RUNNING' in output
    assert 'Local URL: http://127.0.0.1:54731' in output
    assert 'Port: 54731' in output
    assert 'bearer token required' not in output
    assert 'Access Token field' not in output
    assert SYNTHETIC_TOKEN not in output
    assert 'API Token:' not in output
    assert events[-1] == ('closed',)
    assert capsys.readouterr().out == ''


def test_invalid_configuration_prevents_startup_and_prints_no_banner(
    tmp_path, monkeypatch, capsys
):
    settings = Settings(tmp_path, 'too-short', port=54731)
    monkeypatch.setattr('backend.services.executables.configure_tool_environment', lambda: None)
    monkeypatch.setattr(Settings, 'from_env', classmethod(lambda cls: settings))
    monkeypatch.setattr(
        server_module,
        'make_server',
        lambda *args, **kwargs: pytest.fail('server must not bind'),
    )
    with pytest.raises(ValueError, match='AVA_API_TOKEN'):
        server_module.main()
    assert capsys.readouterr().out == ''
