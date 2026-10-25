import os
from pathlib import Path
from .base import Results, asset, json_lines, argv_prefix
from ..services.integrity import blocks_execution, verify_digest
from ..services.target_validation import normalize_target
NAME = 'subfinder'
COMMANDS = ('subfinder',)
VERSION_ARGS = ['-version']
IDENTITY = 'subfinder'


def integrity_status(executable):
    """Report the approved-digest status for the resolved binary (never executes it)."""
    return verify_digest(NAME, executable)


def integrity_error(executable):
    """A refusal message when the pinned digest cannot be satisfied, else None."""
    status = integrity_status(executable)
    return status['message'] if blocks_execution(status['status']) else None


def configuration_error():
    provider = os.getenv('AVA_SUBFINDER_PROVIDER_CONFIG')
    return 'Configured Subfinder provider file is unavailable.' if provider and not Path(provider).is_file() else None


def runtime_status():
    """Honest runtime-configuration reporting for the tool inventory.

    Reports only what is actually configured, rather than asserting that
    "environment configuration is present" when nothing has been set. The
    approved local binary is supplied through AVA_SUBFINDER_PATH; provider keys
    live in the operator's own provider file and are never read, logged or
    reported by PATROLMAN.
    """
    provider = os.getenv('AVA_SUBFINDER_PROVIDER_CONFIG')
    if provider and not Path(provider).is_file():
        return 'configuration_required', 'The configured Subfinder provider file is unavailable.'
    if provider:
        return 'configured', ('Operator provider file is configured. Keys inside it stay in that file and are never read, logged or '
                              'reported; enumeration is limited to the exact authorized domain.')
    return 'configured', ('No provider file is configured; built-in default providers are used. Providers without operator keys may be unavailable, '
                          'and discovered subdomains are inventory only, never scan permission.')


def command(executable, target, profile, output, rate_limit=None):
    provider = os.getenv('AVA_SUBFINDER_PROVIDER_CONFIG')
    if provider and not Path(provider).is_file(): raise ValueError('Subfinder provider configuration missing.')
    rl = str(min(2, max(1, int(rate_limit)))) if rate_limit is not None else '2'
    return [*argv_prefix(executable), *(['-pc', provider] if provider else []), '-d', normalize_target(target), '-json', '-silent', '-rl', rl, '-timeout', '10', '-max-time', '1', '-duc']



def parse(text, target):
    result = Results()
    for row in json_lines(text):
        host = normalize_target(row['host'])
        # Only strict subdomains of the exact authorized domain are discoveries.
        # The apex is the target the operator already authorized (not a newly
        # found host), and the '.'-prefixed check rejects suffix look-alikes such
        # as 'evil-example.com' or 'example.com.attacker.net'.
        if host != target and host.endswith('.' + target):
            result.assets.append(asset(host, 'subdomain', source='subfinder', provider=row.get('source'),
                                       passive=True, authorized_for_scanning=False))
    return result
