from .base import Results, asset, json_lines, web_url, argv_prefix
NAME = 'httpx'
COMMANDS = ('httpx',)
VERSION_ARGS = ['-version']
IDENTITY = 'Current Version:'


def command(executable, target, profile, output, rate_limit=None):
    rl = str(min(2, max(1, int(rate_limit)))) if rate_limit is not None else '2'
    return [*argv_prefix(executable), '-u', web_url(target), '-json', '-silent', '-status-code', '-title', '-tech-detect',
            '-no-fallback-scheme', '-threads', '1', '-rate-limit', rl, '-timeout', '5', '-retries', '0',
            '-response-size-to-read', '1048576', '-disable-update-check', '-no-stdin']



def parse(text, target):
    result = Results()
    for row in json_lines(text):
        if row.get('failed'):
            raise ValueError('HTTP probe failed.')
        if row.get('url', '').rstrip('/') != target.rstrip('/'):
            raise ValueError('httpx returned an out-of-scope URL.')
        result.assets.append(asset(target, 'web', status_code=row.get('status_code'), title=row.get('title'),
                                   technologies=row.get('tech', []), web_server=row.get('webserver'), source='httpx'))
    return result
