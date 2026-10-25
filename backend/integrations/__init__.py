# Nine active tools. The retired web-server scanner is deliberately absent: no
# adapter, registry entry, resolution path or orchestration branch can launch it,
# and its safety evidence is retained under docs/.
from . import nmap, subfinder, httpx_scanner, whatweb, nuclei, sslyze, wapiti, gitleaks, trivy
ADAPTERS = {module.NAME: module for module in (nmap, subfinder, httpx_scanner, whatweb, nuclei, sslyze, wapiti, gitleaks, trivy)}
