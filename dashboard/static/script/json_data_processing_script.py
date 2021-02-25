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
    '''

    @return:list of vulnerable port AND list of tuple of vulnerable ip associated and related port
    '''
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
    '''

    @param list_of_tuple: list of ip asscociated with vuln port
    @param port: targeted port for an attack
    @return: vulnerable ip related to the targeted port
    '''
    ip_vuln_spe_port = []
    for tuple in list_of_tuple:
        if port in tuple:
            ip_vuln_spe_port.append(tuple[0])
    return ip_vuln_spe_port

def session_organised_exploit(json_session):
    '''

    @param json_session: json of the created sessions
    @return: string of specific import data from the json of the created sessions
    '''
    organised_liste = []
    for id in [*json_session]:
        num = id
        exploit = json_session[id]['via_exploit']
        os = json_session[id]['platform']
        ip = json_session[id]['session_host']
        organised_liste.append('n° id '+num+' ; '+'exploit utilisé : '+exploit+' ; '+'type d\'OS : '+os+' ; '+'adresse ip : '+ip)
    return organised_liste







