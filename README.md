# Installation de l'environnement virtuel

Commande :
* sudo apt install python3-venv

# Gestion de l'environnement virtuel python

## Création

Commande :
* python3 -m venv python3_env

## Activation de l'environnement

Commande :
* source python3_env/bin/activate
	
## Installation des dépendances

Commande :
* python3 -m pip install -r requirements.txt

# Lancement du programme

Commande :
* python3 manage.py runserver

Puis connectez-vous à l'adresse suivante : 127.0.0.1:8000/dashboard

## Metasploit

Pour utiliser le module métasploit, au préalable, tapez les commandes suivantes :

Commande :
* sudo msfconsole
* load msgrpc Pass=1234LOL (dans la msfconsole)
