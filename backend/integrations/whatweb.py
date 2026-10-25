import json
from .base import Results, asset, web_url, argv_prefix
NAME = 'whatweb'

COMMANDS = ('whatweb',)
VERSION_ARGS = ['--version']
IDENTITY = 'WhatWeb'
FILE_OUTPUT = True


def command(executable, target, profile, output):
    # `executable` can be a string path or an argv prefix list (e.g. on Windows with a shim).
    return [*argv_prefix(executable), '--aggression=1', '--max-threads=1', '--follow-redirect=never', '--open-timeout=5',
            '--read-timeout=5', '--log-json=' + str(output), web_url(target)]



def parse(text, target):
    rows = json.loads(text)
    if not isinstance(rows, list):
        raise ValueError('Expected WhatWeb array.')
    result = Results()
    for row in rows:
        if row.get('target', '').rstrip('/') != target.rstrip('/'):
            raise ValueError('WhatWeb returned an out-of-scope URL.')
        result.assets.append(asset(target, 'technology', plugins=row.get('plugins', {}), source='whatweb'))
    return result
