from django.shortcuts import render
from django.views.decorators.cache import cache_control
from .forms import Input_for_Test, Formulaire_entree, Selection_entree, Checkbox_args_entree, \
    Formulaire_entree_search_metasploit, Formulaire_entree_run_metasploit, Formulaire_entree_options_metasploit, \
    Formulaire_entree_options_arg_metasploit, Formulaire_entree_payload_metasploit, Type_var_metasploit, \
    Formulaire_entree_prompt_metasploit, Type_var_payload_metasploit, Formulaire_entree_payload_option_metasploit, \
    Formulaire_entree_payload_option_val_metasploit, Choice_module, IP_cible_entree, Port_de_la_cible, Nombre_de_paquet

import sys
import os
import time

import pdb

# add executables' folder path
ProjectFileDir = os.path.dirname(os.path.abspath(__file__))
DashboardScriptDir = os.path.join(ProjectFileDir, 'static/script/')
sys.path.append(DashboardScriptDir)

from metasploit_script import Msfrpc
# Create your views here.

def home_page(request):
    '''

    @param request: request made by the user on the web page
    @return: the view for the home page
    '''
    from extra_scripts import setup_shell
    setup_shell()
    time.sleep(3)
    return render(request, 'dashboard/home/home.html', {})


def apropos(request):
    '''

    @param request: request made by the user on the web page
    @return: the view for the about page
    '''
    return render(request, 'dashboard/home/apropos.html', {})


@cache_control(no_cache=True, must_revalidate=True, no_store=True)  # flush the cache page
def external(request):
    '''

    @param request: request made by the user on the web page
    @return: the view for the test's module
    '''
    form = Input_for_Test(request.POST)

    if form.is_valid():

        if request.method == 'POST' and 'run_script' in request.POST:
            # import function to run
            from test_script import main

            inp = request.POST.get('test_str')
            # test section
            # print(inp)

            # call function
            data = main(inp)

            # renderer
            return render(request, 'dashboard/home/test.html', {'form': form, 'data': data})

    return render(request, 'dashboard/home/test.html', {'form': form})


@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def nmap_visu(request):
    '''

    @param request: request made by the user on the web page
    @return: the view for the nmap's module
    '''
    # save data module
    global data_nmap
    import pickle

    type_scan = Selection_entree(request.POST)
    ip_cible = Formulaire_entree(request.POST)
    arguments = Checkbox_args_entree(request.POST)

    if type_scan.is_valid() and ip_cible.is_valid() and arguments.is_valid() and request.method == 'POST' and 'run_script' in request.POST:

        if request.method == 'POST' and 'run_script' in request.POST:
            # import function to run
            from nmap_script import main
            from pass_crypt import crypted_json

            type_scan_val = request.POST.get('scan_wanted')
            ip_cible_val = request.POST.get('entry_str')
            arguments_val = request.POST.getlist('arguments_checkbox')

            # test section
            # print(type_scan_val)
            # print(ip_cible_val)
            # print(arguments_val)

            # call function
            data = main(type_scan_val, ip_cible_val, arguments_val)

            # delete useless data (!!!!!!!!!!!!!!!!!!!!!!!!CHANGE JSON TREATMENT !!!!!!!!!!!!!!!!!!)
            del data['stats']
            del data['runtime']
            data_nmap = data

            # Store data (serialize)
            with open('dashboard/static/.transit/filename.pickle', 'wb') as handle:
                pickle.dump(crypted_json(data_nmap), handle, protocol=pickle.HIGHEST_PROTOCOL)

            # renderer
            return render(request, 'dashboard/home/nmap_console.html',
                          {'type_scan_val': type_scan_val, 'ip_cible_val': ip_cible_val, 'arguments_val': arguments_val,
                           'data': data})

    return render(request, 'dashboard/home/nmap_console.html',
                  {'type_scan': type_scan, 'ip_cible': ip_cible, 'arguments': arguments})


@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def metasploit_visu(request):
    '''

    @param request: request made by the user on the web page
    @return: the metasploit's module
    '''

    # creation of flag
    global flag_connection
    global flag_search
    global flag_run
    global flag_option
    global flag_payload
    global flag_error
    global flag_auxiliary_ready_to_run
    global flag_choice
    global flag_payload_value

    # global var
    global module_choice
    global session
    global status_connection
    global env

    # global form
    global list_of_module
    global new_list
    global module_run
    global module_description
    global module_options
    global module_missing_required
    global module_running_config
    global module_targetpayload
    global payload_chosen
    global payload_runoptions
    global payload_runoptions_save
    global payload_missing_required
    global json_payload
    data = None

    champ_de_recherche = Formulaire_entree_search_metasploit(request.POST)
    champ_du_run = Formulaire_entree_run_metasploit(request.POST)
    champ_de_l_option = Formulaire_entree_options_metasploit(request.POST)
    champ_de_l_arg_de_option = Formulaire_entree_options_arg_metasploit(request.POST)
    champ_du_payload = Formulaire_entree_payload_metasploit(request.POST)
    champ_de_la_config_payload = Formulaire_entree_payload_option_metasploit(request.POST)
    champ_de_la_val_de_la_config_payload = Formulaire_entree_payload_option_val_metasploit(request.POST)

    type_module = Choice_module(request.POST)
    type_de_var = Type_var_metasploit(request.POST)
    type_de_var_payload = Type_var_payload_metasploit(request.POST)

    champ_du_prompt = Formulaire_entree_prompt_metasploit(request.POST)

    #############################CONNECTION RPC CLIENT ################################
    if request.method == 'POST' and 'run_script' in request.POST:

        # initiate environement
        env = Msfrpc()

        # call function
        env.launch_metasploit()
        env.connection_rpc()

        if env.client is not None:
            flag_connection = "connected"
            status_connection = "connected"

        #retry
        else:
            env.launch_metasploit()
            time.sleep(5)
            env.connection_rpc()

        if env.client is None:
            flag_connection = None
            status_connection = "échec"

        else:
            flag_connection = "connected"
            status_connection = "connected"

        # renderer
        return render(request, 'dashboard/home/metasploit_console.html',
                      {'flag_connection': flag_connection, 'champ_de_recherche': champ_de_recherche,
                       'type_module': type_module, 'status_connection': status_connection})

    ##############################PRE-SELECTION MODULE'S TYPE ###############################
    if request.method == 'POST' and 'run_display_module' in request.POST:

        # checked pseudo~~~flag
        flag_choice = "True"
        # test section

        # call function
        module_choice = request.POST.get('module_wanted')

        # print(module_choice)

        if module_choice == "EXPLOIT":

            env.get_exploits()
            list_of_module = env.list_of_exploit

        elif module_choice == "AUXILIARY":

            env.get_auxiliaries()
            list_of_module = env.list_of_auxiliaries

        # renderer
        return render(request, 'dashboard/home/metasploit_console.html',
                      {'flag_connection': flag_connection, 'list_of_module': list_of_module,
                       'champ_de_recherche': champ_de_recherche, 'type_module': type_module,
                       'flag_choice': flag_choice, 'status_connection': status_connection})

    #################################SELECTION OF ATTACK'S MOODULE###################
    if champ_de_recherche.is_valid() and request.method == 'POST' and 'run_search' in request.POST:

        ######################################EXPLOIT SECTION####################################
        if module_choice == "EXPLOIT":

            word_wanted = request.POST.get('search_str')

            # checked pseudo~~~flag
            flag_search = "True"

            # test section

            # call function
            env.get_exploits()
            list_of_exploit = env.list_of_exploit

            # create new list
            new_list = []

            for i in range(0, len(list_of_exploit), 1):

                if word_wanted in list_of_exploit[i]:
                    new_list.append(list_of_exploit[i])

            # render
            return render(request, 'dashboard/home/metasploit_console.html',
                          {'flag_connection': flag_connection, 'new_list': new_list,
                           'champ_de_recherche': champ_de_recherche, 'flag_search': flag_search,
                           'champ_du_run': champ_du_run, 'type_module': type_module,
                           'flag_choice': flag_choice, 'status_connection': status_connection})

        ######################################AUXILIARY SECTION##################################
        elif module_choice == "AUXILIARY":

            word_wanted = request.POST.get('search_str')

            # checked pseudo~~~flag
            flag_search = "True"

            # test section

            # call function
            env.get_auxiliaries()
            list_of_auxiliary = env.list_of_auxiliaries

            # create new list
            new_list = []

            for i in range(0, len(list_of_auxiliary), 1):

                if word_wanted in list_of_auxiliary[i]:
                    new_list.append(list_of_auxiliary[i])

            # render
            return render(request, 'dashboard/home/metasploit_console.html',
                          {'flag_connection': flag_connection, 'new_list': new_list,
                           'champ_de_recherche': champ_de_recherche, 'flag_search': flag_search,
                           'champ_du_run': champ_du_run, 'type_module': type_module,
                           'flag_choice': flag_choice, 'status_connection': status_connection})

    #######################################CHOICE MODULE IN LIST###############################
    if champ_de_recherche.is_valid() and champ_du_run.is_valid() and type_de_var.is_valid() and request.method == 'POST' and 'run_run' in request.POST:

        ######################################EXPLOIT SECTION####################################
        if module_choice == "EXPLOIT":

            module_wanted = request.POST.get('run_str')
            env.run_an_exploit(module_wanted)

            if env.current_exploit is None:
                # checked pseudo~~~flag
                flag_run = None

                return render(request, 'dashboard/home/metasploit_console.html',
                              {'flag_connection': flag_connection, 'new_list': new_list,
                               'champ_de_recherche': champ_de_recherche, 'flag_search': flag_search,
                               'champ_du_run': champ_du_run, 'type_module': type_module,
                               'flag_choice': flag_choice, 'status_connection': status_connection})

            else:
                # checked pseudo~~~flag
                flag_run = "True"

                module_description, module_options, module_missing_required, module_running_config, module_targetpayload = env.current_exploit.description, env.current_exploit.options, env.current_exploit.missing_required, env.current_exploit.runoptions, env.current_exploit.targetpayloads

                return render(request, 'dashboard/home/metasploit_console.html',
                              {'flag_connection': flag_connection, 'new_list': new_list,
                               'champ_de_recherche': champ_de_recherche, 'flag_search': flag_search,
                               'champ_du_run': champ_du_run, 'module_description': module_description,
                               'module_options': module_options, 'module_missing_required': module_missing_required,
                               'flag_run': flag_run, 'module_running_config': module_running_config,
                               'champ_de_l_option': champ_de_l_option,
                               'champ_de_l_arg_de_option': champ_de_l_arg_de_option, 'type_de_var': type_de_var,
                               'type_module': type_module,
                               'flag_choice': flag_choice, 'status_connection': status_connection})

        ######################################AUXILIARY SECTION##################################
        elif module_choice == "AUXILIARY":

            module_wanted = request.POST.get('run_str')
            env.run_an_auxiliary(module_wanted, client)

            if env.current_auxiliary is None:
                # checked pseudo~~~flag
                flag_run = None

                return render(request, 'dashboard/home/metasploit_console.html',
                              {'flag_connection': flag_connection, 'new_list': new_list,
                               'champ_de_recherche': champ_de_recherche, 'flag_search': flag_search,
                               'champ_du_run': champ_du_run,
                               'type_module': type_module,
                               'flag_choice': flag_choice,
                               'status_connection': status_connection})

            else:
                # checked pseudo~~~flag
                flag_run = "True"

                module_description, module_options, module_missing_required, module_running_config = env.current_auxiliary.description, env.current_auxiliary.options, env.current_auxiliary.missing_required, env.current_auxiliary.runoptions

                # save in an other var the current config

                return render(request, 'dashboard/home/metasploit_console.html',
                              {'flag_connection': flag_connection, 'new_list': new_list,
                               'champ_de_recherche': champ_de_recherche, 'flag_search': flag_search,
                               'champ_du_run': champ_du_run, 'module_description': module_description,
                               'module_options': module_options, 'module_missing_required': module_missing_required,
                               'flag_run': flag_run, 'module_running_config': module_running_config,
                               'champ_de_l_option': champ_de_l_option,
                               'champ_de_l_arg_de_option': champ_de_l_arg_de_option, 'type_de_var': type_de_var,
                               'type_module': type_module,
                               'flag_choice': flag_choice,
                               'status_connection': status_connection})

    #######################################CONFIG MODULE###############################
    if champ_de_recherche.is_valid() and champ_du_run.is_valid() and type_de_var.is_valid() and champ_de_l_option.is_valid() and request.method == 'POST' and 'run_option' in request.POST:

        ######################################EXPLOIT SECTION####################################
        if module_choice == "EXPLOIT":

            option_wanted = request.POST.get('option_str')
            option_arg_wanted = request.POST.get('option_arg_str')
            type_wanted_arg = request.POST.get('type_wanted')

            flag_option = None

            flag_check = env.change_option_exploit(option_wanted, option_arg_wanted, type_wanted_arg)

            if flag_check is None:

                return render(request, 'dashboard/home/metasploit_console.html',
                              {'flag_connection': flag_connection, 'new_list': new_list,
                               'champ_de_recherche': champ_de_recherche, 'flag_search': flag_search,
                               'champ_du_run': champ_du_run, 'module_description': module_description,
                               'module_options': module_options, 'module_missing_required': module_missing_required,
                               'flag_run': flag_run, 'module_running_config': module_running_config,
                               'champ_de_l_option': champ_de_l_option,
                               'champ_de_l_arg_de_option': champ_de_l_arg_de_option, 'type_de_var': type_de_var,
                               'type_module': type_module,
                               'flag_choice': flag_choice,
                               'status_connection': status_connection})

            else:

                module_running_config = env.current_exploit.runoptions

                # refresh data about the exploit
                if option_wanted in module_missing_required:
                    module_missing_required.remove(option_wanted)

                # checked pseudo~~~flag
                if len(module_missing_required) == 0:
                    #     # checked pseudo~~~flag
                    flag_option = "True"

                    env.get_payloads()
                    module_targetpayload = env.list_of_payloads

                return render(request, 'dashboard/home/metasploit_console.html',
                              {'flag_connection': flag_connection, 'new_list': new_list,
                               'champ_de_recherche': champ_de_recherche, 'flag_search': flag_search,
                               'champ_du_run': champ_du_run, 'module_description': module_description,
                               'module_options': module_options, 'flag_run': flag_run,
                               'module_missing_required': module_missing_required,
                               'module_running_config': module_running_config,
                               'champ_de_l_option': champ_de_l_option,
                               'champ_de_l_arg_de_option': champ_de_l_arg_de_option, 'flag_option': flag_option,
                               'type_de_var': type_de_var, 'module_targetpayload': module_targetpayload,
                               'champ_du_payload': champ_du_payload,
                               'type_module': type_module,
                               'flag_choice': flag_choice,
                               'status_connection': status_connection})

        ######################################AUXILIARY SECTION####################################
        elif module_choice == "AUXILIARY":

            option_wanted = request.POST.get('option_str')
            option_arg_wanted = request.POST.get('option_arg_str')
            type_wanted_arg = request.POST.get('type_wanted')

            flag_check = env.change_option_auxiliary(option_wanted, option_arg_wanted, type_wanted_arg)

            if flag_check is None:

                return render(request, 'dashboard/home/metasploit_console.html',
                              {'flag_connection': flag_connection, 'new_list': new_list,
                               'champ_de_recherche': champ_de_recherche, 'flag_search': flag_search,
                               'champ_du_run': champ_du_run, 'module_description': module_description,
                               'module_options': module_options, 'module_missing_required': module_missing_required,
                               'flag_run': flag_run, 'module_running_config': module_running_config,
                               'champ_de_l_option': champ_de_l_option,
                               'champ_de_l_arg_de_option': champ_de_l_arg_de_option,
                               'type_de_var': type_de_var,
                               'type_module': type_module,
                               'flag_choice': flag_choice,
                               'status_connection': status_connection})

            else:

                flag_auxiliary_ready_to_run = None
                module_running_config = env.current_auxiliary.runoptions

                # refresh data about the exploit
                if option_wanted in module_missing_required:
                    module_missing_required.remove(option_wanted)

                # checked pseudo~~~flag
                if len(module_missing_required) == 0:
                    #     # checked pseudo~~~flag
                    flag_auxiliary_ready_to_run = "True"

                return render(request, 'dashboard/home/metasploit_console.html',
                              {'flag_connection': flag_connection, 'new_list': new_list,
                               'champ_de_recherche': champ_de_recherche, 'flag_search': flag_search,
                               'champ_du_run': champ_du_run, 'module_description': module_description,
                               'module_options': module_options, 'flag_run': flag_run,
                               'module_missing_required': module_missing_required,
                               'module_running_config': module_running_config,
                               'champ_de_l_option': champ_de_l_option,
                               'champ_de_l_arg_de_option': champ_de_l_arg_de_option,
                               'flag_auxiliary_ready_to_run': flag_auxiliary_ready_to_run,
                               'type_de_var': type_de_var,
                               'type_module': type_module,
                               'flag_choice': flag_choice,
                               'status_connection': status_connection})

    #######################################PAYLOAD CHOICE###############################
    if champ_de_recherche.is_valid() and champ_du_run.is_valid() and type_de_var.is_valid() and champ_de_l_option.is_valid() and type_de_var_payload.is_valid() and champ_de_la_config_payload.is_valid() and champ_de_la_val_de_la_config_payload.is_valid() and request.method == 'POST' and 'run_payload_choice' in request.POST:

        payload_wanted = request.POST.get('payload_str')
        env.run_a_payload(payload_wanted)
        payload_chosen = env.current_payload

        if payload_chosen is None:
            return render(request, 'dashboard/home/metasploit_console.html',
                          {'flag_connection': flag_connection, 'new_list': new_list,
                           'champ_de_recherche': champ_de_recherche, 'flag_search': flag_search,
                           'champ_du_run': champ_du_run, 'module_description': module_description,
                           'module_options': module_options, 'flag_run': flag_run,
                           'module_missing_required': module_missing_required,
                           'module_running_config': module_running_config,
                           'champ_de_l_option': champ_de_l_option,
                           'champ_de_l_arg_de_option': champ_de_l_arg_de_option, 'flag_option': flag_option,
                           'type_de_var': type_de_var, 'module_targetpayload': module_targetpayload,
                           'champ_du_payload': champ_du_payload,
                           'type_module': type_module,
                           'flag_choice': flag_choice,
                           'status_connection': status_connection})

        else:
            # checked pseudo~~~flag
            flag_payload = "True"
            payload_runoptions = env.current_payload.runoptions
            payload_missing_required = env.current_payload.missing_required


            return render(request, 'dashboard/home/metasploit_console.html',
                          {'flag_connection': flag_connection, 'new_list': new_list,
                           'champ_de_recherche': champ_de_recherche, 'flag_search': flag_search,
                           'champ_du_run': champ_du_run, 'module_description': module_description,
                           'module_options': module_options, 'flag_run': flag_run,
                           'module_missing_required': module_missing_required,
                           'module_running_config': module_running_config,
                           'champ_de_l_option': champ_de_l_option,
                           'champ_de_l_arg_de_option': champ_de_l_arg_de_option, 'flag_option': flag_option,
                           'type_de_var': type_de_var, 'module_targetpayload': module_targetpayload,
                           'champ_du_payload': champ_du_payload, 'payload_chosen': payload_chosen,
                           'champ_de_la_config_payload': champ_de_la_config_payload,
                           'champ_de_la_val_de_la_config_payload': champ_de_la_val_de_la_config_payload,
                           'payload_runoptions': payload_runoptions,
                           'payload_missing_required': payload_missing_required,
                           'type_de_var_payload': type_de_var_payload, 'flag_payload': flag_payload,
                           'type_module': type_module,
                           'flag_choice': flag_choice,
                           'status_connection': status_connection})

    #######################################CONFIG PAYLOAD###############################
    if champ_de_recherche.is_valid() and champ_du_run.is_valid() and type_de_var.is_valid() and champ_de_l_option.is_valid() and type_de_var_payload.is_valid() and champ_de_la_config_payload.is_valid() and champ_de_la_val_de_la_config_payload.is_valid() and request.method == 'POST' and 'run_payload_option' in request.POST:

        payload_option_arg = request.POST.get('payload_option_str')
        payload_option_val = request.POST.get('payload_option_value_str')
        payload_option_type = request.POST.get('type_payload_wanted')

        flag_payload_value = None

        flag_check = env.change_option_payload(payload_option_arg, payload_option_val, payload_option_type,)

        if flag_check is None:

            return render(request, 'dashboard/home/metasploit_console.html',
                          {'flag_connection': flag_connection, 'new_list': new_list,
                           'champ_de_recherche': champ_de_recherche, 'flag_search': flag_search,
                           'champ_du_run': champ_du_run, 'module_description': module_description,
                           'module_options': module_options, 'flag_run': flag_run,
                           'module_missing_required': module_missing_required,
                           'module_running_config': module_running_config,
                           'champ_de_l_option': champ_de_l_option,
                           'champ_de_l_arg_de_option': champ_de_l_arg_de_option, 'flag_option': flag_option,
                           'type_de_var': type_de_var, 'module_targetpayload': module_targetpayload,
                           'champ_du_payload': champ_du_payload, 'payload_chosen': payload_chosen,
                           'champ_de_la_config_payload': champ_de_la_config_payload,
                           'champ_de_la_val_de_la_config_payload': champ_de_la_val_de_la_config_payload,
                           'payload_runoptions': payload_runoptions,
                           'payload_missing_required': payload_missing_required,
                           'type_de_var_payload': type_de_var_payload, 'flag_payload': flag_payload,
                           'type_module': type_module,
                           'flag_choice': flag_choice,
                           'status_connection': status_connection})

        else:

            payload_runoptions = env.current_payload.runoptions

            # refresh data about the exploit
            if payload_option_arg in payload_missing_required:
                payload_missing_required.remove(payload_option_arg)

            # checked pseudo~~~flag
            if len(payload_missing_required) == 0:
                #     # checked pseudo~~~flag
                flag_payload_value = "True"

            return render(request, 'dashboard/home/metasploit_console.html',
                          {'flag_connection': flag_connection, 'new_list': new_list,
                           'champ_de_recherche': champ_de_recherche, 'flag_search': flag_search,
                           'champ_du_run': champ_du_run, 'module_description': module_description,
                           'module_options': module_options, 'flag_run': flag_run,
                           'module_missing_required': module_missing_required,
                           'module_running_config': module_running_config,
                           'champ_de_l_option': champ_de_l_option,
                           'champ_de_l_arg_de_option': champ_de_l_arg_de_option, 'flag_option': flag_option,
                           'type_de_var': type_de_var, 'module_targetpayload': module_targetpayload,
                           'champ_du_payload': champ_du_payload, 'payload_chosen': payload_chosen,
                           'champ_de_la_config_payload': champ_de_la_config_payload,
                           'champ_de_la_val_de_la_config_payload': champ_de_la_val_de_la_config_payload,
                           'type_de_var_payload': type_de_var_payload, 'payload_runoptions': payload_runoptions,
                           'payload_missing_required': payload_missing_required,
                           'flag_payload': flag_payload, 'flag_payload_value': flag_payload_value,
                           'type_module': type_module,
                           'flag_choice': flag_choice,
                           'status_connection': status_connection})

    #######################################RUN EXPLOIT AND HACK###############################
    if champ_de_recherche.is_valid() and champ_du_run.is_valid() and type_de_var.is_valid() and champ_de_l_option.is_valid() and request.method == 'POST' and 'run_exploit' in request.POST:

        # checked pseudo~~~flag
        flag_error = "True"

        json_payload, session = env.execute_exploit()

        # json_payload = True

        print(json_payload)

        if json_payload == -1:
            error = "Echec de la création de la session"

            return render(request, 'dashboard/home/metasploit_console.html',
                          {'flag_connection': flag_connection, 'new_list': new_list,
                           'champ_de_recherche': champ_de_recherche, 'flag_search': flag_search,
                           'champ_du_run': champ_du_run, 'module_description': module_description,
                           'module_options': module_options, 'flag_run': flag_run,
                           'module_missing_required': module_missing_required,
                           'module_running_config': module_running_config,
                           'champ_de_l_option': champ_de_l_option,
                           'champ_de_l_arg_de_option': champ_de_l_arg_de_option, 'flag_option': flag_option,
                           'type_de_var': type_de_var, 'module_targetpayload': module_targetpayload,
                           'champ_du_payload': champ_du_payload, 'payload_chosen': payload_chosen,
                           'champ_de_la_config_payload': champ_de_la_config_payload,
                           'champ_de_la_val_de_la_config_payload': champ_de_la_val_de_la_config_payload,
                           'type_de_var_payload': type_de_var_payload, 'payload_runoptions': payload_runoptions,
                           'flag_payload': flag_payload, 'error': error, 'flag_error': flag_error,
                           'type_module': type_module, 'flag_payload_value': flag_payload_value,
                           'flag_choice': flag_choice,
                           'status_connection': status_connection})
        else:
            return render(request, 'dashboard/home/metasploit_console_prompt.html',
                          {'champ_du_prompt': champ_du_prompt})

    #######################################RUN AUXILIARY AND HACK###############################
    if champ_de_recherche.is_valid() and champ_du_run.is_valid() and type_de_var.is_valid() and champ_de_l_option.is_valid() and request.method == 'POST' and 'run_auxiliary' in request.POST:

        json, session = env.execute_auxiliary(module_run, client)

        print(json)
        if json == -1:
            error = "Echec de la création de la session"

            # checked pseudo~~~flag
            flag_error = "True"

            return render(request, 'dashboard/home/metasploit_console.html',
                          {'flag_connection': flag_connection, 'new_list': new_list,
                           'champ_de_recherche': champ_de_recherche, 'flag_search': flag_search,
                           'champ_du_run': champ_du_run, 'module_description': module_description,
                           'module_options': module_options, 'flag_run': flag_run,
                           'module_missing_required': module_missing_required,
                           'module_running_config': module_running_config,
                           'champ_de_l_option': champ_de_l_option,
                           'champ_de_l_arg_de_option': champ_de_l_arg_de_option,
                           'flag_auxiliary_ready_to_run': flag_auxiliary_ready_to_run,
                           'error': error, 'flag_error': flag_error,
                           'type_module': type_module,
                           'flag_choice': flag_choice,
                           'status_connection': status_connection})

        else:
            return render(request, 'dashboard/home/metasploit_console_prompt.html',
                          {'champ_du_prompt': champ_du_prompt})

    #######################################PROMPT COMMANDE###############################
    if champ_du_prompt.is_valid() and request.method == 'POST' and 'run_cmd' in request.POST:

        cmd_wanted = request.POST.get('prompt_str')

        output = env.execute_command(cmd_wanted, session)

        # if cmd_wanted == 'exit' :
        #     return render(request, 'dashboard/home/metasploit_console.html', {})

        return render(request, 'dashboard/home/metasploit_console_prompt.html', {'champ_du_prompt': champ_du_prompt,
                                                                                 'output': output})

    return render(request, 'dashboard/home/metasploit_console.html', {})


@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def crafter_port_visu(request):
    '''

    @param request: request made by the user on the web page
    @return: the view for the crafter sessions' module
    '''
    import pdb

    # global var
    global client
    global console
    global sessions_client
    global dict_data
    global data_table

    # global flag
    global flag_error_scan
    global flag_success_scan
    global flag_success_exploit
    global flag_good_id

    champ_de_l_id = Formulaire_entree(request.POST)
    champ_du_prompt = Formulaire_entree_prompt_metasploit(request.POST)

    if request.method == 'POST' and 'run_script_scan' in request.POST:
        from metasploit_script import main_connection, launch_metasploit
        from automate import script_automate_scan

        # pdb.set_trace()

        # launch metasploit
        client, console = main_connection()

        if client == -1:
            launch_metasploit()
            time.sleep(5)
            client, console = main_connection()

        if client == -1:
            flag_error = "True"
            error = 'Cannot connect to remote metasploit console'
            return render(request, 'dashboard/home/exploitcrafter_port_console.html',
                          {flag_error: 'flag_error', error: 'error'})

        dict_data = script_automate_scan(client, console)

        if len(dict_data) != 0:
            flag_success_scan = "True"

            return render(request, 'dashboard/home/exploitcrafter_port_console.html',
                          {'flag_success_scan': flag_success_scan,
                           'dict_data': dict_data})
        else:
            flag_error = "True"
            error = 'Error or nothing can be exploited'
            return render(request, 'dashboard/home/exploitcrafter_port_console.html',
                          {flag_error: 'flag_error', error: 'error'})


    return render(request, 'dashboard/home/exploitcrafter_port_console.html', {})


@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def crafter_version_visu(request):
    '''

    @param request: request made by the user on the web page
    @return: the view for the crafter sessions' module
    '''
    import pdb

    # global var
    global client
    global console
    global sessions_client
    global dict_data
    global data_bruteforce

    # global flag
    global flag_error_scan
    global flag_success_scan
    global flag_bruteforce

    # import function to run
    from metasploit_script import main_connection, launch_metasploit

    # call function
    client, console = main_connection()

    if client == -1:
        launch_metasploit()
        time.sleep(5)
        client, console = main_connection()

    if client == -1:
        flag_error = "True"
        error = 'Cannot connect to remote metasploit console'
        return render(request, 'dashboard/home/exploitcrafter_dbdatabase_console.html',
                      {flag_error: 'flag_error', error: 'error'})

    if request.method == 'POST' and 'run_script_scan' in request.POST:
        from automate import get_board_exploit

        # pdb.set_trace()

        dict_data = get_board_exploit(client)

        if len(dict_data) != 0:
            flag_success_scan = "True"

            return render(request, 'dashboard/home/exploitcrafter_dbdatabase_console.html',
                          {'flag_success_scan': flag_success_scan,
                           'dict_data': dict_data})
        else:
            flag_error = "True"
            error = 'Error or nothing can be exploited'
            return render(request, 'dashboard/home/exploitcrafter_dbdatabase_console.html',
                          {flag_error: 'flag_error', error: 'error'})

    if request.method == 'POST' and 'run_script_brute_force' in request.POST:
        from automate import brute_force_exploit

        # pdb.set_trace()

        dict_session = brute_force_exploit(dict_data, client)

        if len(dict_session) != 0:
            flag_bruteforce = "True"

            return render(request, 'dashboard/home/exploitcrafter_dbdatabase_console.html',
                          {'flag_success_scan': flag_success_scan, 'flag_bruteforce': flag_bruteforce,
                           'dict_data': dict_data, 'dict_session': dict_session})
        else:
            flag_error = "True"
            error = 'Error in looking for session can be exploited'
            return render(request, 'dashboard/home/exploitcrafter_dbdatabase_console.html',
                          {flag_error: 'flag_error', error: 'error', 'flag_success_scan': flag_success_scan,
                           'dict_data': dict_data})

    return render(request, 'dashboard/home/exploitcrafter_dbdatabase_console.html', {})


@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def syn_flood_attack_visu(request):
    ip_de_la_cible = IP_cible_entree(request.POST)
    port_de_la_cible = Port_de_la_cible(request.POST)
    nombre_de_paquet = Nombre_de_paquet(request.POST)

    message = 'no packet sent'

    if ip_de_la_cible.is_valid() and port_de_la_cible.is_valid() and nombre_de_paquet.is_valid() and request.method == 'POST' and 'run_script' in request.POST:
        # pdb.set_trace()

        # import function to run
        from extra_scripts import syn_flood_attack

        ip_target = request.POST.get('ip_flood_syn_target')
        port_target = request.POST.get('port_flood_syn_target')
        number_of_paquet = request.POST.get('paquet_flood_syn_target')

        number_of_paquet = int(number_of_paquet)

        message = 'packet are sent'

        syn_flood_attack(ip_target, port_target, number_of_paquet)
        return render(request, 'dashboard/home/syn_flood_console.html',
                      {'ip_de_la_cible': ip_de_la_cible, 'port_de_la_cible': port_de_la_cible,
                       'nombre_de_paquet': nombre_de_paquet, 'message': message})

    return render(request, 'dashboard/home/syn_flood_console.html',
                  {'ip_de_la_cible': ip_de_la_cible, 'port_de_la_cible': port_de_la_cible,
                   'nombre_de_paquet': nombre_de_paquet, 'message': message})
