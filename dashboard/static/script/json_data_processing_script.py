import json
import sys
import os
import re
from os.path import dirname, abspath
from pass_crypt import uncrypt_json
import pickle
import pdb

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
    port = ['161', '445', '1617', '8020']
    ip_addr = [*nmap_data][:-2]
    port_vuln = []
    ip_vuln = []
    for port_num in port:
        for ip in ip_addr:
            if re.search(r'\b{}\b'.format(port_num), json.dumps(nmap_data[ip])):
                port_vuln.append(port_num)
                ip_vuln.append((ip, port_num))
    return port_vuln, ip_vuln


def look_for_version():
    '''

    @return: list of vulnerable port
    '''

    failures = ['Microsoft Windows Server 2008 R2', 'Windows 7', 'Apache httpd 2.2']
    ip_addr = [*nmap_data][:-2]
    port_vuln_ip = []

    # look for port associated with vulnerable version
    for ip in ip_addr:
        for port in nmap_data[ip]['ports']:
            for failure in failures:
                if failure in json.dumps(port):
                    port_vuln_ip.append((ip, port['portid'], failure))

    return port_vuln_ip


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
        organised_liste.append(
            'n° id ' + num + ' ; ' + 'exploit utilisé : ' + exploit + ' ; ' + 'type d\'OS : ' + os + ' ; ' + 'adresse ip : ' + ip)
    return organised_liste


def get_port_id_and_name():
    ip_addr = [*nmap_data][:-2]
    port_id = ""
    service_name = ""
    data = []

    # pdb.set_trace()
    for ip in ip_addr:
        for port in nmap_data[ip]['ports']:
            port_id = port['portid']
            try:
                service_name = port['service']['product'] + ' / ' +  port['service']['version'] + ' / ' + port['service']['name']
            except:
                try:
                    service_name = port['service']['product'] + ' / ' + ' / ' + port['service']['name']
                except:
                    try:
                        service_name = port['service']['name'] + ' / ' +  port['service']['version']
                    except:
                        try:
                            service_name = port['service']['name']
                        except:
                            service_name = 'no_retrieve'
            data.append((port_id, service_name))

    return data


print(get_port_id_and_name())
