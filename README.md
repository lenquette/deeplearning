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
		load msgrpc Pass=1234LOL (in msfconsole)
		
## Automate/Session Crafter

In order to use the "Session Crafter", there are several actions to do.

First write the following commande lines in a python shell :

		from selenium import webdriver
		from webdriver_manager.firefox import GeckoDriverManager
	
Then, write the following commande in a Linux terminal :

		cp ~/.wdm/drivers/geckodriver/linux64/v0.29.0/geckodriver ~/.local/bin/
		
You may use the "Session Crafter" now !!!



			  .                                                      .
			.n                   .                 .                  n.
		  .   .dP                  dP                   9b                 9b.    .
		 4    qXb         .       dX                     Xb       .        dXp     t
		dX.    9Xb      .dXb    __                         __    dXb.     dXP     .Xb
		9XXb._       _.dXXXXb dXXXXbo.                 .odXXXXb dXXXXb._       _.dXXP
		 9XXXXXXXXXXXXXXXXXXXVXXXXXXXXOo.           .oOXXXXXXXXVXXXXXXXXXXXXXXXXXXXP
		  `9XXXXXXXXXXXXXXXXXXXXX'~   ~`OOO8b   d8OOO'~   ~`XXXXXXXXXXXXXXXXXXXXXP'
		    `9XXXXXXXXXXXP' `9XX'   DIE    `98v8P'  HUMAN   `XXP' `9XXXXXXXXXXXP'
			~~~~~~~       9X.          .db|db.          .XP       ~~~~~~~
				        )b.  .dbo.dP'`v'`9b.odb.  .dX(
				      ,dXXXXXXXXXXXb     dXXXXXXXXXXXb.
				     dXXXXXXXXXXXP'   .   `9XXXXXXXXXXXb
				    dXXXXXXXXXXXXb   d|b   dXXXXXXXXXXXXb
				    9XXb'   `XXXXXb.dX|Xb.dXXXXX'   `dXXP
				     `'      9XXXXXX(   )XXXXXXP      `'
				              XXXX X.`v'.X XXXX
				              XP^X'`b   d'`X^XX
				              X. 9  `   '  P )X
				              `b  `       '  d'
				               `             '


