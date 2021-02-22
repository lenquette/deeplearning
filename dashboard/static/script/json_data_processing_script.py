import json
import sys
import os
from os.path import dirname, abspath
from pass_crypt import uncrypt_json
import pickle

# add pinckle's location folder
ProjectFileDirParent = dirname(dirname(abspath(__file__)))
DashboardTransitDir = os.path.join(ProjectFileDirParent, '.transit/')
sys.path.append(DashboardTransitDir)


# Load data (deserialize)
FileName = os.path.join(DashboardTransitDir, 'filename.pickle')
with open(FileName, 'rb') as handle:
    nmap_data = uncrypt_json(pickle.load(handle))

print(nmap_data)



