import os
import sys
import subprocess
import pdb


###############################SYN FLOOD ATTACK########################################
DashboardScriptDir = os.path.dirname(os.path.abspath(__file__))
PythonSynAttackDir = os.path.join(DashboardScriptDir, 'Python-SYN-Flood-Attack-Tool/')
sys.path.append(PythonSynAttackDir)

from py3_synflood_cmd import SYN_Flood


def syn_flood_attack(dstIP, dstPort, counter):
    '''

    @param dstIP: str ip of the target
    @param dstPort: str of port
    @param counter: int of counter
    @return: 0 or -1 according to the fact that it succeeded or not
    '''
    try :
        SYN_Flood(dstIP, dstPort, counter)
        return 0
    except :
        return -1


#########################################WEBSSH2###############################################
def setup_shell():
    '''
    fonction to setup webssh2 automatically with system-call
    @return: 0 or -1 according to the fact that it succeeded or not
    '''
    color_monitor = Background_printer()
    try :
        os.chdir('additional_features/webssh2/app/')
        cmd = ['npm', 'start'] #begin at ptoject's root location !!!!
        FNULL = open(os.devnull, 'w')
        subprocess.Popen(cmd, stdout=FNULL, stderr=subprocess.STDOUT)
        os.chdir('../../..') #return to original root directory's projetc => other python depends from this element !!!!!!!
        print(color_monitor.background_OKGREEN + "[*] Success in launching webssh2"+
              color_monitor.background_ENDC)
        return 0
    except :
        print(color_monitor.background_FAIL + "[x] Failure in launching webssh2"+
              color_monitor.background_ENDC)
        return -1


#####################################UTILITY REALATED TO PRINT################################

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




