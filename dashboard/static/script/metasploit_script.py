from pymetasploit3.msfrpc import MsfRpcClient


def main_connection():
    global client
    # ip = "127.0.0.1"
    # user = "msf"
    passwd = '1234LOL'
    client = MsfRpcClient(passwd, port=55552)
    return client


def main_display_exploit():
    list_of_exploit = client.modules.exploits
    return list_of_exploit


def main_run_exploit(choosen_exploit):
    global exploit
    try:
        exploit = client.modules.use('exploit', choosen_exploit)
        return exploit
    except:
        return -1


def main_change_option(choosen_option, arg, type_val):
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


def main_see_payload():
    return exploit.targetpayloads()


def main_choose_payload(chosen_payload):
    global payload

    try:
        payload = client.modules.use('payload', chosen_payload)
        return payload
    except:
        return -1


def main_config_payload(chosen_option, val, type_val):

    try :
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


def main_exe_exploit():
    global json
    global session
    try:
        json = exploit.execute(payload=payload)
        session_num_list = [*client.sessions.list]
        # print(session_num_list)
        session_id = session_num_list[0]
        session = client.sessions.session(str(session_id))
        return json
    except:
        return -1


def main_run_prompt(cmd):
    terminating_strs = ['----END----']
    return session.run_with_output(cmd, terminating_strs, timeout=10, timeout_exception=False)
# 10 seconds max
