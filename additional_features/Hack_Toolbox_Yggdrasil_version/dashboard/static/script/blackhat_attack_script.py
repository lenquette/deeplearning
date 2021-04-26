from json_data_processing_script import *
from metasploit_script import *


class Blackhat:
    def __init__(self):
        self.json_monitor = Json_monitor()
        self.env = Msfrpc()
        self.targets_tree = self.json_monitor.get_targets_tree()

        ######################CONNECT YOURSELF TO MSGRPC#######################################################
        self.env.launch_metasploit()
        self.env.connection_rpc()

        ######################STORE INFORMATIONS###############################################################
        self.tree_targets = None

    def correction_with_correlation_table(self, service_name):
        '''
        Method used to make correlation between value given in entry of the method and the table defined in config.ini
        :param service_name: name of the service (string)
        :return: the correlation (string)
        '''
        for correlation in self.json_monitor.correlation_table:
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

    def get_exploits_tree(self):
        '''
        Methode used to create the exploit tree
        :return:
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
                            search_string_for_console_cmd = self.correction_with_correlation_table(
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
                            #############################LAUNCH THE COMMAND AND GET LIST EXPLOIT########################
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
                                            if 'exploit' in item_sub and 'exploit' in item_sub and (
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
        self.tree_targets = dict_of_targets
        ########################################STORE DATA IN JSON FILE#################################################
        print(self.env.color_monitor.background_OKGREEN + "[*] Storing information in {}".format(
            str(self.json_monitor.datapath) + '/data.json') +
              self.env.color_monitor.background_ENDC)
        self.json_monitor.write_json_data_in_a_file(self.json_monitor.datapath + '/data.json', self.tree_targets)


if __name__ == '__main__':
    foo = Blackhat()
    foo.get_exploits_tree()
