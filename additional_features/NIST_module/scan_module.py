'''
!!! Warning !!!
modified nmap3 library to avoid root right for SYN
go to nmap3.py and remove self.require_root()
'''

### Import section ###
######################
import configparser
import sys
import os
import nmap3
import datetime
import multiprocessing
from utilities import Background_printer
from json_data_processing import Json_monitor
from metasploit_utilities import Msfrpc

##########################
### End Import section ###

### Tools generation ###
########################
Color_Monitor = Background_printer()
Json_Monitor = Json_monitor()
Msfrpc_Monitor = Msfrpc()

####################################
### End Tools generation section ###

class Scanner:
    def __init__(self):
        # Initiate the config.ini file
        config = configparser.ConfigParser()
        try:
            config.read(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.ini'))
        except FileExistsError as err:
            print(Color_Monitor.background_FAIL + '[x] File exists error: {}'.format(err),
                  Color_Monitor.background_ENDC)

        # Initiate useful variable
        self.default_always_arg = "--privileged"
        self.default_name = "nmap_report"
        self.nmap = nmap3.NmapScanTechniques()
        self.nmap_version = nmap3.Nmap()

        # Temp data name
        self.filename_tmp = None
        self.directoryname_nmap_scan_tmp = None
        self.directoryname_nmap_tree_tmp = None

        # Coordinator of path
        self.path_data_nmap_save_scan = config['Data_path']['path_save_nmap_scan']
        self.path_data_nmap_save_tree = config['Data_path']['path_save_nmap_tree']
        self.path_data_metasploit_save_scan = config['Data_path']['path_save_metasploit_scans']
        self.path_data_metasploit_save_tree = config['Data_path']['path_save metasploit_trees']

    def IP_range_enumeration(self, IP_network_mask):
        '''
        Function used to enumerate the IP of a network thanks to the IP address of the network and the mask
        :param IP_network_mask: string of the Ip network and the mask as follow '<IP>/<MASK>'
        :return: list of strings which are the IP address of the network
        '''
        list_available_IP = []
        IP_network = IP_network_mask.split('/')[0]
        mask = int(IP_network_mask.split('/')[-1])
        number_of_available_IP = 2 ** (32 - mask) - 2
        # based on the number of available IP and the original IP, get the IPs
        IP_octect = IP_network.split('.')

        for v in range(0, number_of_available_IP, 1):
            for i in range(0, 4, 1):
                # check fist if octect is full
                if IP_octect[i] == 255:
                    IP_octect[i - 1] = IP_octect[i - 1] + 1
                    IP_octect[i] = 0
                    pass
            IP_octect[-1] = str(int(IP_octect[-1]) + 1)
            list_available_IP.append('.'.join(IP_octect))

        return list_available_IP

    def save_data(self, IP, nmap_scan, subfolder=None):
        '''
        Function used to save data of an nmap scan in a json file
        :param IP: string of the IP address of the machine
        :param nmap_scan: json data to save (nmap scan)
        :param subfolder: string of the subfolder for a given scan of a network
        :return: None
        '''
        try:
            filename = self.path_data_nmap_save_scan + subfolder + self.default_name + '_' + IP + '_' + datetime.datetime.today().strftime(
                "%d_%m_%Y__%H_%M_%S") + '.json'
            self.filename_tmp = filename
            Json_Monitor.write_json_data_in_a_file(filename, nmap_scan)
        except Exception as err:
            print(Color_Monitor.background_FAIL + '[x] An error occurs : {}'.format(err),
                  Color_Monitor.background_ENDC)

    def action_asynchrone_nmap_scan(self, type_scan, OS, IP, name_sub_folder):
        '''
        Action made to perform an nmap scan. This goal of this function is to make the nmap scan asynchronous.
        By doing this function related to nmap scan, we will be able (by calling it through multiprocessing and pools)
        to perform asynchronous scan.
        :param type_scan: string of the type of scan performed by nmap
        :param OS: string of the OS dectection options
        :param IP: string of the IP of a machine or a network
        :param name_sub_folder: string of the subfolder for a given scan of a network
        :return: None
        '''
        if OS is None:
            if type_scan == "-SYN":
                nmap_result = self.nmap.nmap_syn_scan(IP, args="--privileged")
                # print log #######################################
                print(
                    Color_Monitor.background_OKGREEN + "[*] Scan of {} done".format(
                        IP) + Color_Monitor.background_ENDC)
                ###################################################
                ###################################################
                # save report #####################################
                self.save_data(IP, nmap_result, name_sub_folder + '/')
                ###################################################
            elif type_scan == "-TCP":
                nmap_result = self.nmap.nmap_tcp_scan(IP, args="--privileged")
                # print log #######################################
                print(
                    Color_Monitor.background_OKGREEN + "[*] Scan of {} done".format(
                        IP) + Color_Monitor.background_ENDC)
                ###################################################
                ###################################################
                # save report #####################################
                self.save_data(IP, nmap_result, name_sub_folder + '/')
                ###################################################
            elif type_scan == "-VERSION":
                nmap_result = self.nmap_version.nmap_version_detection(IP, args="--privileged")
                # print log ########################################
                print(
                    Color_Monitor.background_OKGREEN + "[*] Scan of {} done".format(
                        IP) + Color_Monitor.background_ENDC)
                ###################################################
                # save report #####################################
                self.save_data(IP, nmap_result, name_sub_folder + '/')
                ###################################################
        else:
            if type_scan == "-SYN":
                nmap_result = self.nmap.nmap_syn_scan(IP, args='--privileged -O')
                # print log #######################################
                print(Color_Monitor.background_OKGREEN + "[*] Scan of {} done".format(
                    IP) + Color_Monitor.background_ENDC)
                ###################################################
                # save report #####################################
                self.save_data(IP, nmap_result, name_sub_folder + '/')
                ###################################################
                ###################################################
            elif type_scan == "-TCP":
                nmap_result = self.nmap.nmap_tcp_scan(IP, args='--privileged -O')
                # print log #######################################
                print(Color_Monitor.background_OKGREEN + "[*] Scan of {} done".format(
                    IP) + Color_Monitor.background_ENDC)
                ###################################################
                # save report #####################################
                self.save_data(IP, nmap_result, name_sub_folder + '/')
                ###################################################
            elif type_scan == "-VERSION":
                nmap_result = self.nmap_version.nmap_version_detection(IP, args='--privileged -O')
                # print log #######################################
                print(Color_Monitor.background_OKGREEN + "[*] Scan of {} done".format(
                    IP) + Color_Monitor.background_ENDC)
                ###################################################
                ###################################################
                # save report #####################################
                self.save_data(IP, nmap_result, name_sub_folder + '/')
                ###################################################

    def action_asynchrone_nmap_trees(self, dir, path, name_sub_folder):
        '''
        Action made to perform an nmap tree.An nmap tree is a summary of an nmap scan.
        The goal of this function is to make the nmap tree asynchronous.
        By doing this function related to nmap scan, we will be able (by calling it through multiprocessing and pools)
        to perform asynchronous tree.
        :param dir: string of the directory folder of the nmap scans
        :param path: string of the subfolder of the nmap scan
        :param name_sub_folder: string of the name of the subfolder of the futur directory of nmap trees
        :return:
        '''
        if os.path.isfile(os.path.join(dir, path)):
            try:
                scan = Json_Monitor.read_json_data_in_a_file(dir + '/' + path)
                target_tree = Json_Monitor.get_targets_tree(scan)
                filename = "nmap_tree_" + path.split("_")[2] + datetime.datetime.today().strftime(
                    "__%d_%m_%Y__%H_%M_%S") + '.json'
                Json_Monitor.write_json_data_in_a_file(self.path_data_nmap_save_tree + name_sub_folder + '/' + filename,
                                                       target_tree)
                print(Color_Monitor.background_OKGREEN + "[*] Tree of {} done".format(
                    path.split("_")[2]) + Color_Monitor.background_ENDC)
            except Exception as err:
                print(Color_Monitor.background_FAIL + '[x] An error occurs : {}'.format(err),
                      Color_Monitor.background_ENDC)

    def action_asynchrone_auxiliaries(self, auxiliary, IP, name_sub_folder):
        '''
        Action made to perform a metasploit scan through auxiliaries. Auxiliaries might detect unseen issue from nmap
        standard scan. The goal of this function is to make such scans asynchronous.
        By doing this function related to metasploit auxiliaries, we will be able (by calling it through multiprocessing and pools)
        to perform asynchronous metasploit scan.
        :param auxiliary:
        :param IP:
        :param name_sub_folder:
        :return:
        '''
        # get auxiliary
        Msfrpc_Monitor.execute_console_command("use " + auxiliary + "\n")
        dict_tmp = {}
        try:
            # verify IP
            if len(IP.split('.')) < 4:
                raise Exception("Bad IP")
            # looking for missing requirement
            chosen_auxiliary = Msfrpc_Monitor.client.modules.use('auxiliary', auxiliary)
            for option in chosen_auxiliary.missing_required:
                if option != "RHOSTS":
                    raise Exception(str(option))
            # configure auxiliary
            Msfrpc_Monitor.execute_console_command("set RHOSTS " + IP + "\n")
            # run the auxiliary
            output = Msfrpc_Monitor.execute_console_command("run" + "\n")
            # save result
            dict_tmp[str(auxiliary)] = output
            Json_Monitor.add_json_data_in_a_file(
                self.path_data_metasploit_save_scan + name_sub_folder + "/metasploit_scanner_" + IP + ".json", dict_tmp)
            print(Color_Monitor.background_OKGREEN + "[*] Metasploit scan of {} done".format(IP),
                  Color_Monitor.background_ENDC)

        except Exception as e:
            print(Color_Monitor.background_FAIL + "[x] Failed to run auxiliary due to unknown options : {}".format(
                str(e)),
                  Color_Monitor.background_ENDC)

    def scanner_method(self, args=None):
        '''
        Function used to scan a network asynchronously, through nmap tool
        :param args: list of strings : 1: type of scan ; 2: os detection option ; 3: <IP>/<MASK>
        :return: None
        '''
        # create pool
        pool = multiprocessing.Pool(processes=20)
        nmap_result = None
        nmap_scans = None
        try:
            if len(args) < 4:
                raise Exception("You must defined your arguments, according to the help menu")
            else:
                # create folder for save###
                if len(args[3].split("-")[-1].split("/")) == 1:
                    name_sub_folder = "scans_for_{}".format(args[3].split("-")[-1]).split("/")[
                                          0] + datetime.datetime.today().strftime("__%d_%m_%Y__%H_%M_%S")
                else:
                    name_sub_folder = "scans_for_subnet_{}".format(args[3].split("-")[-1]).split("/")[
                                          0] + datetime.datetime.today().strftime("__%d_%m_%Y__%H_%M_%S")
                os.makedirs(self.path_data_nmap_save_scan + name_sub_folder)
                self.directoryname_nmap_scan_tmp = self.path_data_nmap_save_scan + name_sub_folder
                if args[1] not in ["-SYN", "-TCP", "-VERSION"]:
                    raise Exception("You must chose of the following scan : SYN, TCP, VERSION")
                else:
                    # check if OS detection is wanted
                    if "None" in args[2]:
                        # check if range IP is not wanted
                        if len(args[3].split("-")[-1].split("/")) == 1:
                            if str(args[1]) == "-SYN":
                                nmap_result = self.nmap.nmap_syn_scan(args[3].split("-")[-1])
                            elif str(args[1]) == "-TCP":
                                nmap_result = self.nmap.nmap_tcp_scan(args[3].split("-")[-1])
                            elif str(args[1]) == "-VERSION":
                                nmap_result = self.nmap_version.nmap_version_detection(args[3].split("-")[-1])
                            # print log #######################################
                            print(Color_Monitor.background_OKGREEN + "[*] Scan of {} done".format(
                                args[3].split("-")[-1].split("/")[0]) + Color_Monitor.background_ENDC)
                            ###################################################
                            # save report #####################################
                            self.save_data(args[3].split("-")[-1].split("/")[0], nmap_result, name_sub_folder + '/')
                            ###################################################
                            return 0
                        # if range IP is needed
                        else:
                            for IP in self.IP_range_enumeration(args[3].split("-")[-1]):
                                pool.apply(self.action_asynchrone_nmap_scan,
                                           args=(args[1], None, IP, name_sub_folder))
                            return 0
                    else:
                        # check if range IP is not wanted
                        if len(args[3].split("/")) == 1:
                            if str(args[1]) == "-SYN":
                                nmap_result = self.nmap.nmap_syn_scan(args[3].split("-")[-1], args='--privileged -O')
                            elif str(args[1]) == "-TCP":
                                nmap_result = self.nmap.nmap_tcp_scan(args[3].split("-")[-1], args='--privileged -O')
                            elif str(args[1]) == "-VERSION":
                                nmap_result = self.nmap_version.nmap_version_detection(args[3].split("-")[-1],
                                                                                       args='--privileged -O')

                            # print log ########################################
                            print(Color_Monitor.background_OKGREEN + "[*] Scan of {} done".format(
                                args[3].split("-")[-1].split("/")[0]) + Color_Monitor.background_ENDC)
                            # save report ######################################
                            self.save_data(args[3].split("-")[-1].split("/")[0], nmap_result, name_sub_folder + '/')
                            ####################################################
                            return nmap_result
                        # if range IP is needed
                        else:
                            for IP in self.IP_range_enumeration(args[3].split("-")[-1]):
                                pool.apply_async(self.action_asynchrone_nmap_scan,
                                           args=(args[1], True, IP, name_sub_folder))
                            pool.close()
                            pool.join()
                            return 0

        except Exception as err:
            print(Color_Monitor.background_FAIL + '[x] An error occurs : {}'.format(err),
                  Color_Monitor.background_ENDC)

    def defined_nmap_tree_summary(self, args=None):
        '''
        Function used to define nmap tree asynchronously
        :param args: list of strings : 1: type of scan ; 2: os detection option ; 3: <IP>/<MASK>
        :return:
        '''
        # create pool###
        pool = multiprocessing.Pool(processes=20)
        # create folder for save###
        if len(args[3].split("-")[-1].split("/")) == 1:
            name_sub_folder = "trees_for_{}".format(args[3].split("-")[-1]).split("/")[
                                  0] + datetime.datetime.today().strftime("__%d_%m_%Y__%H_%M_%S")
        else:
            name_sub_folder = "trees_for_subnet_{}".format(args[3].split("-")[-1]).split("/")[
                                  0] + datetime.datetime.today().strftime("__%d_%m_%Y__%H_%M_%S")
        os.makedirs(self.path_data_nmap_save_tree + name_sub_folder)
        # store temp data
        self.directoryname_nmap_tree_tmp = name_sub_folder
        # retrieve data
        dir = self.directoryname_nmap_scan_tmp
        for path in os.listdir(dir):
            pool.apply_async(self.action_asynchrone_nmap_trees, args=(dir, path, name_sub_folder))
        pool.close()
        pool.join()
        # if os.path.isfile(os.path.join(dir, path)):
        #     try:
        #         scan = Json_Monitor.read_json_data_in_a_file(dir + '/' + path)
        #         target_tree = Json_Monitor.get_targets_tree(scan)
        #         filename = "nmap_tree_" + path.split("_")[2] + datetime.datetime.today().strftime(
        #             "__%d_%m_%Y__%H_%M_%S") + '.json'
        #         Json_Monitor.write_json_data_in_a_file(self.path_data_save_tree + name_sub_folder + '/' + filename,
        #                                                target_tree)
        #         print(Color_Monitor.background_OKGREEN + "[*] Tree of {} done".format(
        #             path.split("_")[2]) + Color_Monitor.background_ENDC)
        #     except Exception as err:
        #         print(Color_Monitor.background_FAIL + '[x] An error occurs : {}'.format(err),
        #               Color_Monitor.background_ENDC)

    def scanner_auxiliaries_metasploit(self, args=None):
        '''
        Function used to perform metasploit scan synchronously
        :param args: list of strings : 1: type of scan ; 2: os detection option ; 3: <IP>/<MASK>
        :return:
        '''
        #TODO make it asynchrone when pymetasploit3 will allow output through applicative layer and not only through console

        # create folder for save###
        if len(args[3].split("-")[-1].split("/")) == 1:
            name_sub_folder = "metasploit_scan_for_".format(args[3].split("-")[-1]).split("/")[
                                  0] + datetime.datetime.today().strftime("__%d_%m_%Y__%H_%M_%S")
        else:
            name_sub_folder = "metasploit_scan_for_subnet_{}".format(args[3].split("-")[-1]).split("/")[
                                  0] + datetime.datetime.today().strftime("__%d_%m_%Y__%H_%M_%S")
        os.makedirs(self.path_data_metasploit_save_scan + name_sub_folder)
        # retrieve data
        dir = self.path_data_nmap_save_tree + self.directoryname_nmap_tree_tmp
        # initiate useful variable
        metasploit_auxiliaries_usefull = []
        # launch metasploit
        Msfrpc_Monitor.launch_metasploit()
        # connection to metasploit
        Msfrpc_Monitor.connection_rpc()
        # loop IP
        for path in os.listdir(dir):
            if os.path.isfile(os.path.join(dir, path)):
                # create pool
                # pool = multiprocessing.Pool(processes=20)
                # retrieve list of auxiliaries
                Msfrpc_Monitor.get_auxiliaries()
                # retrieve services
                services = []
                tree_nmap = Json_Monitor.read_json_data_in_a_file(dir + '/' + path)
                for key, sub_dict_port in tree_nmap.items():
                    IP = key
                    try:
                        if key != "os":
                            for key_bis, dict_port_num in sub_dict_port.items():
                                try:
                                    for key_bis_bis, item_value in dict_port_num.items():
                                        try:
                                            for key_bis_bis_bis, item_value_bis in item_value.items():
                                                try:
                                                    if key_bis_bis_bis == "prod_name":
                                                        services.append(item_value_bis)
                                                except:
                                                    pass
                                        except:
                                            pass
                                except:
                                    pass
                    except:
                        pass
                # sort the list
                for auxiliary in Msfrpc_Monitor.list_of_auxiliaries:
                    for name_of_service in services:
                        if "scanner" in auxiliary and name_of_service in auxiliary:
                            metasploit_auxiliaries_usefull.append(auxiliary)
                # use the auxiliaries
                for auxiliary_bis in metasploit_auxiliaries_usefull:
                    self.action_asynchrone_auxiliaries(auxiliary_bis, IP, name_sub_folder)
                    # pool.apply_async(self.action_asynchrone_auxiliaries, args=(auxiliary_bis, IP, name_sub_folder))
                # pool.close()
                # pool.join()
        return 0


if __name__ == '__main__':

    # os.chdir("/home/ludovic/Test_Lab/NIST_module")
    # Scanner_definition = Scanner()
    # Scanner_definition.directoryname_nmap_tree_tmp = 'trees_for_subnet_10.10.13.0__15_11_2021__11_25_41'
    # Scanner_definition.scanner_auxiliaries_metasploit(args=["toto", "-SYN", "-O", "10.10.13.0/28"])
    # Scanner_definition.scanner_method(args=["toto", "-SYN", "-O", "10.10.13.1/30"])
    # Scanner_definition.defined_nmap_tree_summary(args=["toto", "-SYN", "-O", "10.10.13.1/30"])
    # ##
    # launch metasploit
    # Msfrpc_Monitor.launch_metasploit()
    # connection to metasploit
    # Msfrpc_Monitor.connection_rpc()
    # ##
    # # Scanner_definition.action_asynchrone_auxiliaries("auxiliary/scanner/smb/smb_ms17_010", "10.10.13.2", "metasploit_scan_for_subnet_10.10.13.1__28_10_2021__10_17_56")
    # Scanner_definition.scanner_auxiliaries_metasploit(args=["toto", "-SYN", "-O", "10.10.13.1/30"])

    # dir = "data/nmap_scans/scans_for_subnet_10.10.13.0__22_10_2021__10_39_14/"
    # name_sub_folder = "data/nmap_trees/trees_for_subnet_10.10.13.0__25_10_2021__10_58_21/"
    # for path in os.listdir(dir):
    #     if os.path.isfile(os.path.join(dir, path)):
    #         try :
    #             scan = Json_Monitor.read_json_data_in_a_file(dir+path)
    #             target_tree = Json_Monitor.get_targets_tree(scan)
    #             filename = "nmap_tree_" + path.split("_")[2] + datetime.datetime.today().strftime("__%d_%m_%Y__%H_%M_%S") + '.json'
    #             Json_Monitor.write_json_data_in_a_file(name_sub_folder + '/' + filename, target_tree)
    #             print(Color_Monitor.background_OKGREEN + "[*] Tree of {} done".format(
    #                 path.split("_")[2]) + Color_Monitor.background_ENDC)
    #         except Exception as err:
    #             print(Color_Monitor.background_FAIL + '[x] An error occurs : {}'.format(err),
    #                 Color_Monitor.background_ENDC)
    #
    # # os.chdir("/home/ludovic/Test_Lab/NIST_module")
    # # scan = Json_Monitor.read_json_data_in_a_file("data/nmap_scans/scans_for_subnet_10.10.13.0__22_10_2021__10_39_14/nmap_report_10.10.13.1_22_10_2021__10_41_42.json")
    # # name_sub_folder = "data/nmap_trees/trees_for_subnet_10.10.13.0__22_10_2021__11_44_12/"
    # # target_tree = Json_Monitor.get_targets_tree(scan)
    # # filename = "nmap_tree_" + "test" + datetime.datetime.today().strftime("__%d_%m_%Y__%H_%M_%S") + '.json'
    # # Json_Monitor.write_json_data_in_a_file(name_sub_folder + '/' + filename, target_tree)
    # # print(Color_Monitor.background_OKGREEN + "[*] Tree of {} done".format("test") + Color_Monitor.background_ENDC)

    try:
        if sys.argv[1] == "--help":
            Color_Monitor.print_intro_banner()
            print(Color_Monitor.background_OKCYAN + u"""
This module is a test to get back every data that is possible to retrieve from computers in a network.
In order to do so, this programme use nmap. Those are the options needed for this module.

--help , show the help menu

-SYN scan SYN
-TCP scan TCP
-VERSION scan VERSION

-args = -O if you desire os detection
-args = None if you desire none of the previous arguments

-<ip> ip of the target / you might specified a range of ip (for instance : 192.168.100.100/16)

An example to use such a tool is the following line :

python3 scan_module.py -VERSION -None 192.168.100.110/28
            """ + Color_Monitor.background_ENDC)
        else:
            Color_Monitor.print_intro_banner()
            Scanner_definition = Scanner()
            Scanner_definition.scanner_method(args=sys.argv)
            Scanner_definition.defined_nmap_tree_summary(args=sys.argv)
            Scanner_definition.scanner_auxiliaries_metasploit(args=sys.argv)
    except:
        Color_Monitor.print_intro_banner()
        print(Color_Monitor.background_FAIL +
              "Please, check the manual with the option \"--help\"." +
              Color_Monitor.background_ENDC)
        exit()
