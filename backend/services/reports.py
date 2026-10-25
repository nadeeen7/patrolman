import hashlib
import json
import os
import re
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

ENV = Environment(loader=FileSystemLoader(Path(__file__).resolve().parents[1] / 'templates'),
                  autoescape=select_autoescape(['html', 'xml']))


# Windows counts MAX_PATH (260) including the terminating null and this host has
# LongPathsEnabled=0, so an over-long path fails with FileNotFoundError even when
# its directory exists: 259 characters is the longest file that can be opened.
MAX_REPORT_PATH = 259
# Longest name written, because it is produced through a .tmp sibling first.
LONGEST_REPORT_NAME = 'vulnerabilities.json.tmp'
# Path separators between data_dir/reports, the target, the scan id and the file.
SEPARATORS = 3


def report_directory(data_dir, scan):
    target = re.sub(r'[^a-zA-Z0-9_.-]', '_', scan['target'])[:100]
    base = data_dir / 'reports'
    # Keep every report file inside MAX_PATH. Long local-directory targets are
    # shortened deterministically and keep a digest so distinct targets can
    # never share a directory; short targets keep their existing names, so
    # reports written by earlier versions stay where they are.
    room = MAX_REPORT_PATH - len(str(base)) - len(str(scan['id'])) - len(LONGEST_REPORT_NAME) - SEPARATORS
    if len(target) > room:
        digest = hashlib.sha256(scan['target'].encode('utf-8')).hexdigest()[:12]
        target = (target[:max(room - len(digest) - 1, 0)] + '-' + digest)[:max(room, 1)]
    return base / target / scan['id']


def write_reports(data_dir, scan):
    directory = report_directory(data_dir, scan)
    directory.mkdir(parents=True, exist_ok=True)
    files = {'scan.json': json.dumps(scan, indent=2, ensure_ascii=False),
             'vulnerabilities.json': json.dumps(scan['findings'], indent=2, ensure_ascii=False),
             'report.html': ENV.get_template('report.html').render(scan=scan)}
    for filename, content in files.items():
        destination = directory / filename
        # A report download can still hold the previous file open, and Windows
        # cannot replace a file with an open handle. Terminal scans are immutable,
        # so identical content never needs rewriting.
        if destination.is_file():
            try:
                if destination.read_text(encoding='utf-8') == content:
                    continue
            except OSError:
                pass
        temporary = directory / (filename + '.tmp')
        try:
            temporary.write_text(content, encoding='utf-8')
            os.replace(temporary, destination)
        except OSError:
            if not destination.is_file():
                raise
    return directory
