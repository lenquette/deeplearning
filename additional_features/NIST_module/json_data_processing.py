import json
import sys
import os
import time
import codecs
import configparser
from os.path import dirname, abspath
from utilities import Background_printer


class Json_monitor:
    def __init__(self):
        # initiate the color monitor
        self.color_monitor = Background_printer()

        # Initiate the config.ini file
        config = configparser.ConfigParser()
        try:
            config.read(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.ini'))
        except FileExistsError as err:
            print(self.color_monitor.background_FAIL + '[x] File exists error: {}'.format(err),
                  self.color_monitor.background_ENDC)

        ### Retrieve value
        self.os_list = config['State']['os_type'].split('@')
        self.service_list = config['State']['services'].split('@')
        self.correlation_table_services = config['State']['correlations_services'].split('@')
        self.correlation_table_targets = config['State']['correlations_targets'].split('@')
        self.exploits_directory = config['State']['exploits_directory'].split('@')

        ### Temp data
        self.targets_tree = None

    def write_json_data_in_a_file(self, name, data):
        '''
        Method used to write in a json file the data
        :param: name: name of the file (string)
        :param: data: json data to write
        :return:
        '''
        outfile = codecs.open(name, 'w', 'utf-8')
        json.dump(data, outfile, indent=4)
        time.sleep(1.5)
        outfile.close()

    def add_json_data_in_a_file(self, name, data):
        '''
        Method used to add data to an existing json file
        :param: name: name of the file (string)
        :param: data: json data to write
        :return:
        '''
        #retrieve previous data
        try:
            outfile = codecs.open(name, 'r', 'utf-8')
            previous_data = json.load(outfile)
            previous_data.update(data)
            outfile.close()
        except:
            previous_data = data
        #write updated dictionnary
        outfile = codecs.open(name, 'w', 'utf-8')
        json.dump(previous_data, outfile, indent=4)
        time.sleep(1.5)
        outfile.close()

    def read_json_data_in_a_file(self, name):
        '''
        Method used to read data in a json file
        :param name: name of the json file
        :return: data : data of the json file
        '''
        jsonfile = codecs.open(name, 'r', 'utf-8')
        data = json.load(jsonfile)
        jsonfile.close()
        return data

    def get_targets_tree(self, nmap_data):
        '''
        Method used to create the targets tree, based on retrieved nmap's data
        For the ports, looks directly in nmap's data
        For the os, get the value with the biggest number of apparition in 'os_product'
        which is located in the nmap ports' information
        :return: the json target tree
        '''
        ip_addr = [[*nmap_data][0]]
        ###initiate os_dict iteration/detection
        os_iter = {}
        for os in self.os_list:
            os_iter[str(os)] = 0
        self.targets_tree = {}
        ##############################RETRIEVE PORTS/OS#################################################################
        #             _,.-"T
        #       _.--{~    :l
        #     c"     `.    :I
        #     |  .-"~-.\    l     .--.
        #     | Y_r--. Y) ___I ,-"(~\ Y
        #     |[__L__/ j"~=__]~_~\." _/
        #  ___|  \.__.r--<~__.T T/ "~/
        # '--cl___/\ ( () ).,_L_]}--{
        #    `--'   `-^--^\ /___"(~\ Y
        #                  "~7/ \ " `/
        #                   // //]--[
        #                  /> oX |: L
        #                 //  /  `| o\
        #                //. /    I  [
        #               / \]/     l: |
        #              Y.//       `|_I
        #              I_Z         L :]
        #             /".-7        [n]l
        #            Y / /         I //
        #            |] /         /]"/
        #            L:/         //./
        #           [_7      _  // /
        #             _  ,-="_"^K_/  -Row  (Rowan Crawford)
        #            [ ][.-~" ~"-.]
        #     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        ##############################RETRIEVE PORTS/OS#################################################################
        for ip in ip_addr:
            port = {}
            for item, dict_of_ip in nmap_data.items():
                if item == "stats" or item == "runtime":
                    continue
                for dict in dict_of_ip['ports']:
                    tmp = {}
                    try:
                        tmp['prod_name'] = dict['service']['name']
                    except:
                        tmp['prod_name'] = 'unknown'
                    try:
                        tmp['protocol'] = dict['protocol']
                    except:
                        tmp['protocol'] = 'unknown'
                    try:
                        tmp['version'] = dict['service']['version']
                    except:
                        tmp['version'] = 'unknown'
                    try:
                        tmp['name_extended'] = dict['service']['product']
                        #change the service name if the extended name gives more informations
                        for word in dict['service']['product'].split(' '):
                            #treat if "/" in word
                            if '/' in word:
                                word = word.split('/')[0]
                            if word.lower() in self.service_list:
                                tmp['prod_name'] = word.lower()
                    except:
                        tmp['name_extended'] = 'unknown'
                    try:
                        for key in [*os_iter]:
                            if dict['service']['ostype'].lower() == key:
                                os_iter[key] += 1
                    except:
                        a = None  # avoid count

                    port[str(dict['portid'])] = tmp

            self.targets_tree[ip] = {'ports': port, 'os': str(max(os_iter, key=os_iter.get))}
        return self.targets_tree

    def write_log(self, name, data):
        '''
        Method used to write a log
        :param name: name of the log file
        :param data: data to write in the log file
        :return:
        '''
        logfile = codecs.open(name, 'a', 'utf-8')
        logfile.write(data+'\n')
        time.sleep(1.5)
        logfile.close()

