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


def setup_shell():
    '''
    fonction to setup webssh2 automatically with system-call
    @return: 0 or -1 according to the fact that it succeeded or not
    '''
    try :
        os.chdir('additional_features/webssh2/app/')
        cmd = ['npm', 'start'] #begin at ptoject's root location !!!!
        FNULL = open(os.devnull, 'w')
        subprocess.Popen(cmd, stdout=FNULL, stderr=subprocess.STDOUT)
        os.chdir('../../..') #return to original root directory's projetc => other python depends from this element !!!!!!!
        return 0
    except :
        return -1

