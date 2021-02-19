# Installation de l'environnement virtuel

		sudo apt install python3-venv

# Gestion de l'environnement virtuel python

## Création

		python3 -m venv .venv

## Activation de l'environnement

		source .venv/bin/activate
	
## Installation des dépendances

		python3 -m pip install -r requirements.txt

# Lancement du programme

		python3 manage.py runserver

Puis connectez-vous à l'adresse suivante : [127.0.0.1:8000/dashboard](127.0.0.1:8000/dashboard)

## Metasploit

Pour utiliser le module métasploit, au préalable, tapez les commandes suivantes :

		sudo msfconsole
		load msgrpc Pass=1234LOL (dans la msfconsole)
