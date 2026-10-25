import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    api_token: str
    allowed_targets: tuple[str, ...] = ()
    allow_private_targets: bool = False
    port: int = 5055
    allowed_local_roots: tuple[str, ...] = ()
    # Require a database authorization record by default; setting this false
    # is an explicit legacy allowlist-only deployment choice.
    require_authorized_target: bool = True
    # Additional administrator accounts may register through the local UI.
    # Operators running a single-admin installation should set
    # AVA_REGISTRATION_ENABLED=false once the first account exists.
    registration_enabled: bool = True
    # Exact external origins (for example a development frontend behind a
    # host-rewriting proxy) that are allowed to pass the same-origin check.
    # Empty by default: only the request's own origin is trusted. Entries are
    # matched exactly and wildcards are never accepted.
    # Wapiti active web scanning operator opt-in state
    wapiti_enabled: bool = False
    trusted_origins: tuple[str, ...] = ()
    require_api_token: bool = False

    @classmethod
    def from_env(cls):
        from .env_file import load as load_env_file
        load_env_file()
        try:
            port = int(os.getenv('AVA_PORT', '5055'))
        except ValueError:
            port = 0
        return cls(
            data_dir=Path(os.getenv('AVA_DATA_DIR', 'data')).resolve(),
            api_token=os.getenv('AVA_API_TOKEN', ''),
            allowed_targets=tuple(x.strip() for x in os.getenv('AVA_ALLOWED_TARGETS', '').split(',') if x.strip()),
            allow_private_targets=os.getenv('AVA_ALLOW_PRIVATE_TARGETS', 'false').strip().lower() == 'true',
            port=port,
            allowed_local_roots=tuple(x for x in os.getenv("AVA_ALLOWED_LOCAL_ROOTS", "").split(os.pathsep) if x),
            require_authorized_target=os.getenv('AVA_REQUIRE_AUTHORIZED_TARGET', 'true').strip().lower() == 'true',
            registration_enabled=os.getenv('AVA_REGISTRATION_ENABLED', 'true').strip().lower() == 'true',
            wapiti_enabled=os.getenv('AVA_WAPITI_ENABLED', 'false').strip().lower() == 'true',
            trusted_origins=tuple(
                value.strip().rstrip('/')
                for value in os.getenv('AVA_TRUSTED_ORIGINS', '').split(',')
                if value.strip()
            ),
            require_api_token=os.getenv('AVA_REQUIRE_API_TOKEN', 'false').strip().lower() == 'true',
        )

    def validate(self):
        # Messages name the fix and never the value.
        token = self.api_token
        if self.require_api_token and not token:
            raise ValueError(
                'AVA_API_TOKEN is not set. Recover your existing token and run '
                '.\\Start-Patrolman.ps1 -SetupCredential, or set it for the PowerShell '
                'session that starts the backend (or in the git-ignored .env file at the '
                'project root). See README "Native Windows quick start". The value is '
                'never displayed.'
            )
        if token:
            if token.startswith('REPLACE_WITH_'):
                raise ValueError(
                    'AVA_API_TOKEN still holds the .env.example placeholder. Replace it with '
                    'your own token of at least 32 characters; the placeholder is not a '
                    'usable credential.'
                )
            if token != token.strip() or '\n' in token or '\r' in token:
                raise ValueError(
                    'AVA_API_TOKEN must not contain surrounding whitespace or line breaks. '
                    'Check for stray quotes or line wrapping in the PowerShell assignment or '
                    '.env file; the value is not displayed.'
                )
            if len(token) < 32:
                raise ValueError(
                    f'AVA_API_TOKEN must contain at least 32 characters (the configured '
                    f'value has {len(token)}); the value is not displayed.'
                )
        if not 1 <= self.port <= 65535:
            raise ValueError('AVA_PORT must be a port between 1 and 65535.')
        for origin in self.trusted_origins:
            parts = urlsplit(origin)
            if (parts.scheme not in {'http', 'https'} or not parts.netloc
                    or parts.username or parts.password
                    or parts.path not in {'', '/'} or parts.query or parts.fragment):
                raise ValueError(
                    'AVA_TRUSTED_ORIGINS entries must be exact http(s) origins '
                    'without credentials, paths, queries or fragments.'
                )
