


    ██╗  ██╗ █████╗  ██████╗██╗  ██╗    ████████╗ ██████╗  ██████╗ ██╗     ██████╗  ██████╗ ██╗  ██╗
    ██║  ██║██╔══██╗██╔════╝██║ ██╔╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔══██╗██╔═══██╗╚██╗██╔╝
    ███████║███████║██║     █████╔╝        ██║   ██║   ██║██║   ██║██║     ██████╔╝██║   ██║ ╚███╔╝
    ██╔══██║██╔══██║██║     ██╔═██╗        ██║   ██║   ██║██║   ██║██║     ██╔══██╗██║   ██║ ██╔██╗
    ██║  ██║██║  ██║╚██████╗██║  ██╗       ██║   ╚██████╔╝╚██████╔╝███████╗██████╔╝╚██████╔╝██╔╝ ██╗
    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═════╝  ╚═════╝ ╚═╝  ╚═
    
                                                         
    イグヅラジル ヴエルシオン

# Virtual environment installation

    sudo apt install python3-venv

# Manage your virtual environment

## Build

    python3 -m venv .venv

## Activation

    source .venv/bin/activate
	
## Dependences installation

    python3 -m pip install -r requirements.txt
		
If it fails on a "wheel", before retrying the previous command, do :

    pip3 install wheel

## Poweroff the virtual environment

    deactivate

# Launch programm

    python3 manage.py runserver

Then, connect yourself to : [127.0.0.1:8000/dashboard](127.0.0.1:8000/dashboard)

# Metasploit 
## It's automatic now

To use metasploit's module, enter the following commands :

    sudo msfconsole
    load msgrpc Pass=1234LOL (in msfconsole)
		
# Automate/Session Crafter (depreciated)

In order to use "Session Crafter", there are several actions to do.

First of all, install the webdriver-manager in a terminal linux:
        
    pip3 webdriver-manager

First, write the following command lines in a python shell :

    from selenium import webdriver
    from webdriver_manager.firefox import GeckoDriverManager

    driver = webdriver.Firefox(executable_path=GeckoDriverManager().install())

	
Then, write the following commande in a Linux terminal :

    cp ~/.wdm/drivers/geckodriver/linux64/v0.29.0/geckodriver ~/.local/bin/
		
NB : To run a python shell with Django in your virtual environment :
		
    python3 
    ...
    exit
		
You may use the "Session Crafter" now !!!

# Black Hat Attack (might be changed to Hellhound)

To use this module, you must first launch an nmap through the graphical interface. Then go to "Black Hat Attack" and launch the module.

# Pymetasploit3

In pymetasploit3, change the request_post definition to set a timeout of 5.0 seconds

    ... request.post(..., timeout = 5.0) ...

# SYN attack module

To use this module, you must change users's rights on python3, thanks to the command 'setcap'.

To do so, write the following command line :

    setcap cap_net_raw=eip /usr/bin/python3.8

You may use the "SYN attack module" now !!!

# Embedded shell
## It's automatic now

To use the embedded shell, do the following command :

First, install OpenSSH :

    $ sudo apt install openssh
    $ sudo service ssh status
    [!] to check if the server is running

Then :

    $ npm install --save read-config@1 (once)
    $ cd additional_features/webssh2/app
    $ npm install --production (once)
    $ npm audit fix (once)
    $ npm start


You may use "Embedded shell" now !!! Go on http://localhost:2222/ssh/host/127.0.0.1

		&@@@@@@@@@&&&&&&@&@@@@@@@@@&&&&&&&&&&&%&&&%%%#(((###/////////////*********,,,,,,
		&@@@@@@@@@@&&&&&&@@@@@@@@@@@@@&@&&@&@&&&&&&&&%%%%###(#(((//**/**/**********,,,,,
		&@@@@@@@@@@@@&@&&@@@@@@@&&&&&&&&&&&@@&&&&&&&&&%%&%%%%%###(*//(///************,,,
		@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&&&&&&&&&&%#(((((#(//////************,,
		@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&&&&&&@&&&&%###((((((//////***,*******
		@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&&&&&&&&&&&%%((((((,**///**********
		@@@@@@&&&&@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&@&&&&&&%&%%#####(((/,////******
		@@@@@&&&&&&&&&&@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&&&&&&&&&&&%%#####((//********
		@@@@@&&&&&&&&&@@@@@@@@@&&&&%%%%%&&&&@@@@@@@@@@@@@@@@&&&@&&&&&&&&%%%%%%#/*/******
		@@@@@&&&&&&&@&&@@@@@%/#((//((((((((#%%&&@@@@@@@@@@@@@@@&&&@&&&@@@&&%(####(/////*
		@@@@@&&&&&@@&&@&@@@%#(*/*****//*****/((%%@@@@@@@@@@@@@@@@&&&@&&&@@&&&&&%%#(/**//
		@&%&&&&&&&&&&&@@@@&((/**,,,,**********/#%@@@&&%&@@@@@@@@@@@&&&@&&&@&&&&&%%##(///
		@@&&&&&&&&&&&@@@@@((//*,*.,...........**%@@@%%%###%@@@@@@@@@@&&&@&&&&&&&&&%%##((
		@@&&%%%%&&&&%&&&@&(/****..       .......(&&&#(##//(##%@@@@@@@@&&&&@&&&&&@@&&&%%#
		@@&&%%%%&&&%#&&&@%#/***,.,,.   .........*&&&#(,,,,**/(##@@@@@@@@@&&@@&&&&@@@&&&%
		&&&&%%%%&&&##&&@@%#(***,,,,,,,,,....,.,,#&&@&(*,,,,,,/((#%@@@@@@@@&&&@&&&&@@@@&&
		&&&&%%%%%&&#(#&@@&%(//*,.,,*,,*,,,,,,,,,%&@@&(,,,,,,*,**/##%@@@@@@@@@&&@&&&@@@@@
		&&&%%&%%%&&&#(#&@@%%(/**,,,,*,,,,,.,,,,,(&@@@#**,,,,,,,.,/(#%@@@@@@@@@&&@&&&@@@@
		&&&&%%%%%%&&&##%&@@%#**,,,,*,,*,,,,,,,,,/&@@&/,,,,*,,,. .*/(#%@@@@@@@@@@&&&&@@@@
		&&&%%%%%%%%%&&###&@@&%/**..,,,*,,,,,,,,,*#&@&/,,,,,,,,*,*(###%&@@@@@@@@&&&&&@@@@
		&&%%%%%%%%#%&%%##(#@@@&%(/,,.,,..... ....,/##..,.,,,**/**/(#%%&@@&%%&@@@@@@@@@@@
		&&&%%%%##%%%%%%%%##(%&@@@&%#///,,*,,,..,,.,,*,..,**/**((/(#&@@&%%%%%&&@@@@@@@@@@
		%%%%%%%%%#####%%%%%%#(##%&@@@@#/(##(/(/(//((/////////,*&@&&%%%%&%&&&&@@@@@@@@@@@
		%%%%%%%%####(###%%%%%%%#(#%%%&&&&%&%%&&&&&&&&&&&&&&&&&&##%%%&&&&&&&&@@@@@@@@@@@@
		###############(###%%%%%%%%%%%%%%%%##%%%%%&&&&&&&%%#%%%&&&&&&&&&&&@@@@@@@@@&@@@@
		((####################%%%%%%%&&&&&%&&&&&%%&&&&%&&&&&&&&&&&&&&&&&@@@@@@@@@@@@@@@&
		((((((((####((########%%%%&&&%%%%%&&&&&&&%&&&&&%&&&%%&&%&&&&&@@@@@@@@&@@@@@@@@@@
		/(/((((((((((##########%%%%%&&&&&&&&&&&&%&&&%#&%%%&%%&&&&&@@@@@@@@@@@@@@@@@@@@@@
		*//////((((((((((((#####%#%%%%%%%&&&&&&&&&&&%&&%&&&&&&@&&&@@@@@@@@@@@@@@@@@@@@@@
		*****//////(((((((########%%%%%%%%%&&&&&&&&&&&&&@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@






