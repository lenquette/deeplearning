# Virtual environment installation

		sudo apt install python3-venv

# Manage your virtual environment

## Build

		python3 -m venv .venv

## Activation

		source .venv/bin/activate
	
## Dependences installation

		python3 -m pip install -r requirements.txt

# Launch programm

		python3 manage.py runserver

Then, connect yourself to : [127.0.0.1:8000/dashboard](127.0.0.1:8000/dashboard)

## Metasploit

To use metasploit's module, enter the following commands :

		sudo msfconsole
		load msgrpc Pass=1234LOL (dans la msfconsole)
