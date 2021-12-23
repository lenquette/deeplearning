import json
import sys
import os
import re
import time
import codecs
import configparser
from os.path import dirname, abspath
from extra_scripts import *
from pass_crypt import uncrypt_json
import pickle


class Json_monitor:
    def __init__(self):
        # initiate the color monitor
        self.color_monitor = Background_printer()
        # add pinckle's location folder
        ProjectFileDirParent = dirname(dirname(abspath(__file__)))
        DashboardTransitDir = os.path.join(ProjectFileDirParent, '.transit/')
        sys.path.append(DashboardTransitDir)

        # Load data (deserialize)
        FileName = os.path.join(DashboardTransitDir, 'filename.pickle')
        with open(FileName, 'rb') as handle:
            self.nmap_data = uncrypt_json(pickle.load(handle))

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
        self.datapath = config['Common']['data_path']
        self.save_path_ia_data = str(config['Common']['save_path'])
        self.save_ia_data_file = str(config['Common']['save_file'])
        self.targets_tree = None

    def look_for_ip_targets(self):
        '''
        Optionnal methode for test verification
        Return the ip of the targets
        :return:
        '''
        return [*self.nmap_data]

    #@property #??? Brung by PyCharm
    def get_targets_tree(self):
        '''
        Method used to create the targets tree, based on retrieved nmap's data
        For the ports, looks directly in nmap's data
        For the os, get the value with the biggest number of apparition in 'os_product'
        which is located in the nmap ports' information
        :return: the json target tree
        '''
        ip_addr = [*self.nmap_data]
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
            for ip, dict_of_ip in self.nmap_data.items():
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


    def read_json_data_in_a_file(self, name):
        '''
        Method used to read data in a json file
        :param name: name of the json file
        :return: date : data of the json file
        '''
        jsonfile = codecs.open(name, 'r', 'utf-8')
        data = json.load(jsonfile)
        jsonfile.close()
        return data

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

#######################################DEPRECIATED##################################################
####################################################################################################


def session_organised_exploit(json_session):
    '''

    @param json_session: json of the created sessions
    @return: string of specific import data from the json of the created sessions
    '''
    organised_liste = []
    for id in [*json_session]:
        num = id
        exploit = json_session[id]['via_exploit']
        os = json_session[id]['platform']
        ip = json_session[id]['session_host']
        organised_liste.append(
            'n° id ' + num + ' ; ' + 'exploit utilisé : ' + exploit + ' ; ' + 'type d\'OS : ' + os + ' ; ' + 'adresse ip : ' + ip)
    return organised_liste


def get_port_id_and_name(ip_addr):
    '''
    @param ip_addr: given ip (str format) of the machine
    @return: list of tuple, according to nmap_data, which is arranged like that : [('port', 'product / version / name '),...]
    '''
    ################CHECK IF GIVEN IP IS RIGHT#####################
    ip_addr_list = [*nmap_data]
    if ip_addr not in ip_addr_list:
        return -1

    port_id = ""
    service_name = ""
    data = []

    # pdb.set_trace()
    for port in nmap_data[ip_addr]['ports']:
        port_id = port['portid']
        try:
            service_name = port['service']['product'] + ' / ' + port['service']['version'] + ' / ' + \
                           port['service']['name']
        except:
            try:
                service_name = port['service']['product'] + ' / ' + ' / ' + port['service']['name']
            except:
                try:
                    service_name = port['service']['name'] + ' / ' + port['service']['version']
                except:
                    try:
                        service_name = port['service']['name']
                    except:
                        service_name = 'no_retrieve'
        data.append([port_id, service_name])

    return data


def create_requete_for_exploitdb(data):
    '''
    @param data: list of tuple (port_num, version)
    @return: dictionnary with => key:port_number ; values:version_name_transformed (by the way,
    we mean 'version_name'+'x.x' with x.x as the number of the version)
    '''
    list_of_requete = {}
    string_num = None

    for liste in data:

        # pdb.set_trace()
        # create list relative au data for the query
        list_of_data_list = liste[1].split(' / ')
        port = liste[0]

        # if there is only one data
        if len(list_of_data_list) == 1:
            list_of_requete[port] = list_of_data_list[0]

        else:
            # treat product by removing name with only min (better search for exploitdb)
            list_product = list_of_data_list[0].split(' ')
            for word in list_product:
                try:
                    flag = float(word)
                except:
                    flag = None

                if flag is None:
                    if word == word.lower() and word not in '+-=~#!:/.;?,''({})@^$£µ%§|':
                        list_product.remove(word)

            string_word = ' '.join(list_product)
            list_of_data_list[0] = string_word

            # treat '-' and keep the first part after split
            list_product = list_of_data_list[0].split('-')
            list_of_data_list[0] = list_product[0]

            # print(list_of_data_list)
            # get the two fisrt number of version if version only contain number
            version = list_of_data_list[1]
            try:
                num_unit = version.split('.')[0]
                num_deci = version.split('.')[1]
                string_num = num_unit + '.' + num_deci
                flag = float(string_num)
            except:
                flag = None

            # store the future request
            if flag is not None:
                list_of_requete[port] = list_of_data_list[0] + ' ' + string_num

            else:
                list_of_requete[port] = list_of_data_list[0]

    return (list_of_requete)


def improve_research(data):
    '''

    @param data: list of requests already made
    @return: deleted salt, noisy data and doubled data
    '''

    # delete doubled data
    port_list = list(set([*data]))

    for port in port_list:
        # pdb.set_trace()
        # suppress noisy data
        try:
            if data[port] == 'unknown':
                del data[port]
        except:
            a = None
        try:
            if data[port] == 'no_retrieve':
                del data[port]
        except:
            a = None
        try:
            if '/' in data[port]:
                # pdb.set_trace()
                data[port] = data[port].split('/')[0]
        except:
            a = None

    for port in data:
        ###exception salt###
        if 'Jenkins' in data[port]:
            data[port] = 'Jenkins'

        if 'ManageEngine Desktop Central' in data[port]:
            data[port] = 'ManageEngine Desktop Central'

    return data
