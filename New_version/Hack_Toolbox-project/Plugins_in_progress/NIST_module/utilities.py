class Background_printer:

    def __init__(self):
        self.background_HEADER = '\033[95m'
        self.backgrounf_OKBLUE = '\033[94m'
        self.background_OKCYAN = '\033[96m'
        self.background_OKGREEN = '\033[92m'
        self.background_WARNING = '\033[93m'
        self.background_FAIL = '\033[91m'
        self.background_ENDC = '\033[0m'
        self.background_BOLD = '\033[1m'
        self.background_UNDERLINE = '\033[4m'

    def print_intro_banner(self):
        '''
        Function used to print begin process banner
        :return: None
        '''
        print(self.background_OKGREEN + u"""
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   _______       __                    
  / ____(_)___  / /_  ___  _____       
 / /   / / __ \/ __ \/ _ \/ ___/       
/ /___/ / /_/ / / / /  __/ /           
\____/_/ .___/_/ /_/\___/_/            
 _    /_/__                            
| |     / /_  ___________ ___          
| | /| / / / / / ___/ __ `__ \         
| |/ |/ / /_/ / /  / / / / / /         
|__/|__/\__, /_/  /_/ /_/ /_/          
    ___/____/  _                       
   / __ \_____(_)   ______ ________  __
  / /_/ / ___/ / | / / __ `/ ___/ / / /
 / ____/ /  / /| |/ / /_/ / /__/ /_/ / 
/_/   /_/  /_/ |___/\__,_/\___/\__, /  
                              /____/     (イグヅラジル ヴエルシオン)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^""" + self.background_ENDC)


