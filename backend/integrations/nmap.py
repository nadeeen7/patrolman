from xml.etree import ElementTree as ET
from .base import Results, asset, literal, argv_prefix

NAME = 'nmap'
COMMANDS = ('nmap',)
VERSION_ARGS = ['--version']
IDENTITY = 'Nmap version'
# Port 8080 is deliberately excluded so a local developer proxy or desktop
# security tool is never probed as part of an assessment.
PORTS = {'quick': '80,443,8000,8443', 'standard': '21,22,25,53,80,110,139,143,443,445,3306,3389,5432,8000,8443',
         'comprehensive': '21,22,25,53,80,110,135,139,143,389,443,445,465,587,636,993,995,1433,1521,3306,3389,5432,5900,6379,8000,8443,9200,27017'}


def command(executable, target, profile, output, rate_limit=None, target_port=None):
    ip = literal(target)
    # The host timeout must outlast a full port sweep. Windows silently drops
    # SYNs to filtered ports, so each one consumes its connect timeout: measured
    # comprehensive sweeps here take 64-85s and intermittently exceeded a 60s/75s
    # cap. When that happened Nmap aborted mid-sweep and reported no ports at all,
    # silently starving every web tool of discovery. 120s outlasts the sweep, and
    # parse() now rejects that silent case instead of reporting zero findings.
    max_rate = str(min(20, max(1, int(rate_limit)))) if rate_limit is not None else '20'
    ports = PORTS[profile]
    if target_port is not None:
        port_str = str(target_port)
        port_list = [p.strip() for p in ports.split(',')]
        if port_str not in port_list:
            ports = f'{ports},{port_str}'
    return [*argv_prefix(executable), *(['-6'] if ':' in ip else []), '-sT', *(['-sV', '--version-light'] if profile != 'quick' else []), '-Pn', '-n', '-T2', '--max-rate', max_rate,
            '--max-retries', '1', '--host-timeout', '120s', '-p', ports, '-oX', '-', ip]



def parse(text, target):
    if '<!ENTITY' in text.upper():
        raise ValueError('XML entities prohibited.')
    root = ET.fromstring(text)
    if root.tag != 'nmaprun':
        raise ValueError('Not Nmap XML.')
    finished = root.find('runstats/finished')
    if finished is None or finished.get('exit') != 'success':
        raise ValueError('Nmap did not report successful completion.')
    result = Results()
    for host in root.findall('host'):
        if host.get('timedout') == 'true':
            raise ValueError('Nmap host timed out.')
        for address in host.findall('address'):
            if address.get('addrtype') in {'ipv4', 'ipv6'} and literal(address.get('addr')) != literal(target):
                raise ValueError('Nmap returned an out-of-scope host.')
        up = host.find('status') is not None and host.find('status').get('state') == 'up'
        # A completed sweep always emits a <ports> element (possibly only
        # <extraports>); its absence means Nmap gave up before scanning ports, so
        # reporting "no open ports" would be a false negative.
        if up and host.find('ports') is None:
            raise ValueError('Nmap did not finish the port sweep for an up host (host timeout).')
        if up:
            result.assets.append(asset(target, 'host', observation='Host reported up by Nmap; -Pn assumes host up.'))
        for port in host.findall('ports/port'):
            if port.find('state') is None or port.find('state').get('state') != 'open':
                continue
            number = int(port.get('portid'))
            service = port.find('service')
            metadata = dict(service.attrib) if service is not None else {}
            result.assets.append(asset(target, 'port', port=number, protocol=port.get('protocol'),
                                       service=metadata, status='observed'))
    return result
