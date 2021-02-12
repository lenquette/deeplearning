from pymetasploit3.msfrpc import MsfRpcClient

def main_connection() :
	global client
	#ip = "127.0.0.1"
	#user = "msf"
	passwd = 'Oirlbiz5'
	client = MsfRpcClient(passwd, port=55552)
	return client

def main_display_exploit():
	client = main_connection()
	list_of_exploit = client.modules.exploits
	return list_of_exploit


def main_run_exploit(choosen_exploit):
	exploit = client.modules.use('exploit', choosen_exploit)
	return exploit, exploit.description, exploit.options, exploit.missing_required
