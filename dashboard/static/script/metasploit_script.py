from pymetasploit3.msfrpc import MsfRpcClient, MsfConsole
import time
import subprocess, os

def launch_metasploit():
    '''

    @return: 0 (not really usefull)
    '''
    cmd = ["msfdb", "init", "--user", "ludovic", "--pass", "' '"]
    cmd2 = ["msfconsole", "-x load msgrpc Pass=1234LOL"]
    FNULL = open(os.devnull, 'w')
    subprocess.Popen(cmd, stdout=FNULL, stderr=subprocess.STDOUT)
    time.sleep(5)
    subprocess.Popen(cmd2, stdout=FNULL, stderr=subprocess.STDOUT)
    return 0


def main_connection():
    '''

    @return: client and console if it succeeded or -1, -1 if it failed
    '''
    # ip = "127.0.0.1"
    # user = "msf"
    passwd = '1234LOL'
    try:
        client = MsfRpcClient(passwd, port=55552)
        console = MsfConsole(client)
        # print(client)
    except:
        client = -1
        console = -1
    return client, console


def main_display_exploit(client):
    '''

    @param client: rpc client from metasploit console
    @return: list of exploit
    '''
    list_of_exploit = client.modules.exploits
    return list_of_exploit


def main_display_auxiliary(client):
    '''

    @param client: rpc client from metasploit console
    @return: list of exploit
    '''
    list_of_auxiliary = client.modules.auxiliary
    return list_of_auxiliary


def main_run_exploit(chosen_exploit, client):
    '''

    @param chosen_exploit: str of the chosen exploit
    @param client: rpc client from metasploit console
    @return: exploit or -1 if it failed
    '''
    try:
        exploit = client.modules.use('exploit', chosen_exploit)
        return exploit
    except:
        return -1


def main_run_auxiliary(chosen_auxiliary, client):
    '''

    @param chosen_auxiliary: str of the chosen auxiliary
    @param client: rpc client from metasploit console
    @return: auxiliary or -1 if it failed
    '''
    try:
        auxiliary = client.modules.use('auxiliary', chosen_auxiliary)
        return auxiliary
    except:
        return -1


def main_change_option_exploit(choosen_option, arg, type_val, exploit):
    '''

    @param choosen_option: exploit's option that will be change
    @param arg: if it is STR, INT, or BOOL type
    @param type_val: the value ralated to the change of the option
    @param exploit: chosen exploit
    @return: list of the configured option for the chosen exploit or -1 if it failed
    '''
    try:
        if type_val == "INT":
            arg = int(arg)
        elif type_val == "BOOL":
            arg = bool(arg)
        else:
            exploit[choosen_option] = arg

        exploit[choosen_option] = arg

        return exploit.runoptions

    except:
        return -1


def main_change_option_auxiliary(choosen_option, arg, type_val, auxiliary):
    '''

    @param choosen_option: auxiliary's option that will be change
    @param arg: if it is STR, INT, or BOOL type
    @param type_val: the value related to the change of the option
    @param auxiliary: chosen auxiliary
    @return: list of the configured option for the chosen auxiliary or -1 if it failed
    '''
    try:
        if type_val == "INT":
            arg = int(arg)
        elif type_val == "BOOL":
            arg = bool(arg)
        else:
            auxiliary[choosen_option] = arg

        auxiliary[choosen_option] = arg

        return auxiliary.runoptions

    except:
        return -1


def main_see_payload(exploit):
    '''

    @param exploit: chosen exploit
    @return: list of payloads related to the chosen exploit
    '''
    return exploit.targetpayloads()


def main_choose_payload(chosen_payload, client):
    '''

    @param chosen_payload: chosen payload
    @param client: rpc client from metasploit console
    @return: payload or -1 if it failed
    '''
    try:
        payload = client.modules.use('payload', chosen_payload)
        return payload
    except:
        return -1


def main_config_payload(chosen_option, val, type_val, payload):
    '''

    @param chosen_option: payload's option that will be change
    @param val: if it is STR, INT, or BOOL type
    @param type_val: the value related to the change of the option
    @param payload: chosen payload
    @return: list of the configured option for the chosen payload or -1 if it failed
    '''
    try:
        if type_val == "INT":
            val = int(val)
        elif type_val == "BOOL":
            val = bool(val)
        else:
            payload.runoptions[chosen_option] = val

        payload.runoptions[chosen_option] = val

        return payload.runoptions
    except:
        return -1


def main_exe_exploit(payload, exploit, client):
    '''

    @param payload: chosen payload
    @param exploit: chosen exploit
    @param client: rpc client from metasploit console
    @return: json related to the creation of the session and the sessions or -1, -1 if it failed
    '''
    print(client)
    json_exploit = exploit.execute(payload=payload)
    time.sleep(15)
    try:

        session_num_list = [*client.sessions.list]
        session_id = session_num_list[-1]
        session = client.sessions.session(str(session_id))
        return json_exploit, session
    except:
        return -1, -1


def main_enter_console_for_scan(auxiliary, ip, console):
    '''

    @param auxiliary: chosen auxiliary
    @param ip: str of the ip
    @param console: console of the rpc client
    @return: json content of the console
    '''
    try:
        console.write('use ' + auxiliary)
        console.write('set RHOSTS ' + ip)
        console.write('run')
        time.sleep(5)
        return console.read()
    except:
        return -1


def main_exe_auxiliary(auxiliary, client):
    '''

    @param auxiliary:
    @param client:
    @return:
    '''
    json_auxiliary = auxiliary.execute()
    time.sleep(15)
    try:

        session_num_list = [*client.sessions.list]
        session_id = session_num_list[-1]
        session = client.sessions.session(str(session_id))
        return json_auxiliary, session
    except:
        return -1, -1


def main_run_prompt(cmd, session):
    '''

    @param cmd: str command
    @param session: session
    @return: the content dispaly by the shell of the meterpreter
    '''
    if "Meterpreter" in str(type(session)):
        terminating_strs = ['----END----']
        return session.run_with_output(cmd, terminating_strs, timeout=10, timeout_exception=False)
    # 10 seconds max

    elif "Shell" in str(type(session)):
        session.write(cmd)
        return session.read()


def main_enter_console_manual(list_of_string, console):
    '''

    @param list_of_string: str command
    @param console: console of the rpc client
    @return: 0 (not really usefull)
    '''
    for string in list_of_string:
        console.write(string)
        while console.is_busy():
            time.sleep(1)
    return 0


def retrieve_exploit_from_db_info(list_of_rows, client):
    '''

    @param list_of_rows: list of the row extracted from exploitdb after a research
    @param client: rpc metasploit client
    @return: possible exploit according to the database of exploitdb
    '''
    # define keyword global
    keyword_global = ['SMB', 'smb', 'Smb']  # 'Windows', 'windows', 'WINDOWS', 'Server', 'SERVER', 'server',
    keyword_special = ['ms20', 'Ms20', 'MS20', 'ms19', 'Ms19', 'MS19', 'ms18', 'Ms18', 'MS18', 'ms17', 'Ms17', 'MS17',
                       'ms16', 'Ms16', 'MS16', 'ms15', 'Ms15', 'MS15', 'ms14', 'Ms14', 'MS14', 'ms13', 'Ms13', 'MS13',
                       'ms12', 'Ms12', 'MS12', 'ms11', 'Ms11', 'MS11', 'ms10', 'Ms10', 'MS10', 'ms09', 'Ms09', 'MS09',
                       'ms08', 'Ms08', 'MS08', 'ms07', 'Ms07', 'MS07', 'ms06', 'Ms06', 'MS06', 'ms05', 'Ms05', 'MS05',
                       'ms04', 'Ms04', 'MS04', 'ms03', 'Ms03', 'MS03', 'ms02', 'Ms02', 'MS02', 'ms01', 'Ms01', 'MS01',
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
    list_of_exploit = main_display_exploit(client)

    for row in rows_data.items():
        # first search with the global to reduce the loss of time (cause we are going to use damerau levenshtein distance's algorithm after)
        for keyword in row[1]["global"]:
            for exploit in list_of_exploit:
                if keyword.lower() in exploit and exploit not in new_list:
                    new_list.append(exploit)

    # if no global was set, new_list is empty !!!!!!
    if len(new_list) == 0:
        new_list = list_of_exploit

    # then search special keyword
    for row in rows_data.items():
        for keyword in row[1]["special"]:
            for remaining in new_list:
                if keyword.lower() in remaining and remaining not in end_list:
                    end_list.append(remaining)

    exploits_chosen = end_list

    return exploits_chosen

