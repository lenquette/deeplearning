import json
import sys
import os
from os.path import dirname, abspath
from pass_crypt import uncrypt_json
import pickle

# add pinckle's location folder
ProjectFileDirParent = dirname(dirname(abspath(__file__)))
DashboardTransitDir = os.path.join(ProjectFileDirParent, '.transit/')
sys.path.append(DashboardTransitDir)

# Load data (deserialize)
FileName = os.path.join(DashboardTransitDir, 'filename.pickle')
with open(FileName, 'rb') as handle:
    nmap_data = uncrypt_json(pickle.load(handle))


def look_for_port():
    port = ['21', '445', '4848']
    ip_addr = [*nmap_data][:-2]
    port_vuln = []
    ip_vuln = []
    for port_num in port:
        for ip in ip_addr:
            if port_num in json.dumps(nmap_data[ip]):
                port_vuln.append(port_num)
                ip_vuln.append((ip, port_num))
    return port_vuln, ip_vuln


def look_for_ip_associated_port(list_of_tuple, port):
    ip_vuln_spe_port = []
    for tuple in list_of_tuple:
        if port in tuple:
            ip_vuln_spe_port.append(tuple[0])
    return ip_vuln_spe_port





