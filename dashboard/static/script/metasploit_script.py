from pymetasploit3.msfrpc import MsfRpcClient, MsfConsole
import time
def main_connection():
    # ip = "127.0.0.1"
    # user = "msf"
    passwd = '1234LOL'
    client = MsfRpcClient(passwd, port=55552)
    console = MsfConsole(client)
    print(client)
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


def main_run_auxiliary(chosen_auxiliary,client):
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
    #print(payload.runoptions)
    #print(exploit.runoptions)
    #import pdb
    #pdb.set_trace()
    print(client)
    json_exploit = exploit.execute(payload=payload)
    time.sleep(15)
    #print(client.sessions.list)
    try:

        session_num_list = [*client.sessions.list]
        # print(session_num_list)
        session_id = session_num_list[-1]
        session = client.sessions.session(str(session_id))
        return json_exploit, session
    except:
        return -1, -1

def main_enter_console_for_scan(auxiliary):
    try :
        json_scan = auxiliary.execute()
        #print(json_scan)
        return json_scan
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

    if "Meterpreter" in str(type(session)) :
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
