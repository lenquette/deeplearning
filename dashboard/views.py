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

# add executables' folder path
ProjectFileDir = os.path.dirname(os.path.abspath(__file__))
DashboardScriptDir = os.path.join(ProjectFileDir, 'static/script/')
sys.path.append(DashboardScriptDir)


# Create your views here.

def home_page(request):
    '''

    @param request: request made by the user on the web page
    @return: the view for the home page
    '''
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
    global client
    global console
    global status_connection

    # global form
    global list_of_module
    global new_list
    global module_run
    global module_description
    global module_options
    global module_missing_required
    global module_running_config
    global module_running_config_save
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

        # import function to run
        from metasploit_script import main_connection

        # test section

        # call function
        client, console = main_connection()

        if client != -1:
            flag_connection = "connected"
            status_connection = "connected"

        else:
            flag_connection = None
            status_connection = "échec"

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
            from metasploit_script import main_display_exploit

            list_of_module = main_display_exploit(client)

        elif module_choice == "AUXILIARY":
            from metasploit_script import main_display_auxiliary

            list_of_module = main_display_auxiliary(client)

        # renderer
        return render(request, 'dashboard/home/metasploit_console.html',
                      {'flag_connection': flag_connection, 'list_of_module': list_of_module,
                       'champ_de_recherche': champ_de_recherche, 'type_module': type_module,
                       'flag_choice': flag_choice, 'status_connection': status_connection})

    #################################SELECTION OF ATTACK'S MOODULE###################
    if champ_de_recherche.is_valid() and request.method == 'POST' and 'run_search' in request.POST:

        ######################################EXPLOIT SECTION####################################
        if module_choice == "EXPLOIT":

            from metasploit_script import main_display_exploit

            word_wanted = request.POST.get('search_str')

            # checked pseudo~~~flag
            flag_search = "True"

            # test section

            # call function
            list_of_exploit = main_display_exploit(client)

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

            from metasploit_script import main_display_auxiliary

            word_wanted = request.POST.get('search_str')

            # checked pseudo~~~flag
            flag_search = "True"

            # test section

            # call function
            list_of_auxiliary = main_display_auxiliary(client)

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

            from metasploit_script import main_run_exploit

            module_wanted = request.POST.get('run_str')

            module_run = main_run_exploit(module_wanted, client)

            # print(module_run.description)
            # print(module_wanted)

            if module_run == -1:
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

                module_description, module_options, module_missing_required, module_running_config, module_targetpayload = module_run.description, module_run.options, module_run.missing_required, module_run.runoptions, module_run.targetpayloads

                # save in an other var the current config
                module_running_config_save = module_running_config

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

            from metasploit_script import main_run_auxiliary

            module_wanted = request.POST.get('run_str')

            module_run = main_run_auxiliary(module_wanted, client)

            if module_run == -1:
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

                module_description, module_options, module_missing_required, module_running_config = module_run.description, module_run.options, module_run.missing_required, module_run.runoptions

                # save in an other var the current config
                module_running_config_save = module_running_config

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

            from metasploit_script import main_change_option_exploit, main_see_payload

            option_wanted = request.POST.get('option_str')
            option_arg_wanted = request.POST.get('option_arg_str')
            type_wanted_arg = request.POST.get('type_wanted')

            flag_option = None

            module_running_config = main_change_option_exploit(option_wanted, option_arg_wanted, type_wanted_arg,
                                                               module_run)

            if module_running_config == -1:

                # reattribute the previous value
                module_running_config = module_running_config_save

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

                # save in an other var the current config
                module_running_config_save = module_running_config

                # refresh data about the exploit
                if option_wanted in module_missing_required:
                    module_missing_required.remove(option_wanted)

                # checked pseudo~~~flag
                if len(module_missing_required) == 0:
                    #     # checked pseudo~~~flag
                    flag_option = "True"
                    module_targetpayload = main_see_payload(module_run)

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

            from metasploit_script import main_change_option_auxiliary

            option_wanted = request.POST.get('option_str')
            option_arg_wanted = request.POST.get('option_arg_str')
            type_wanted_arg = request.POST.get('type_wanted')

            module_running_config = main_change_option_auxiliary(option_wanted, option_arg_wanted, type_wanted_arg,
                                                                 module_run)

            if module_running_config == -1:

                # reattribute the previous value
                module_running_config = module_running_config_save

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

                # save in an other var the current config
                module_running_config_save = module_running_config

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
        from metasploit_script import main_choose_payload

        payload_wanted = request.POST.get('payload_str')

        payload_chosen = main_choose_payload(payload_wanted, client)

        if payload_chosen == -1:
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
            payload_runoptions = payload_chosen.runoptions
            payload_missing_required = payload_chosen.missing_required

            # save in an other var the current config
            payload_runoptions_save = payload_runoptions

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
        from metasploit_script import main_config_payload

        payload_option_arg = request.POST.get('payload_option_str')
        payload_option_val = request.POST.get('payload_option_value_str')
        payload_option_type = request.POST.get('type_payload_wanted')

        flag_payload_value = None

        payload_runoptions = main_config_payload(payload_option_arg, payload_option_val, payload_option_type,
                                                 payload_chosen)

        if payload_runoptions == -1:

            # reattribute the previous value
            payload_runoptions = payload_runoptions_save

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

            # save in an other var the current config
            payload_runoptions_save = payload_runoptions

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
        from metasploit_script import main_exe_exploit

        # checked pseudo~~~flag
        flag_error = "True"

        json_payload, session = main_exe_exploit(payload_chosen, module_run, client)

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
        from metasploit_script import main_exe_auxiliary

        json, session = main_exe_auxiliary(module_run, client)

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
        from metasploit_script import main_run_prompt

        cmd_wanted = request.POST.get('prompt_str')

        output = main_run_prompt(cmd_wanted, session)

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
        from automate import script_automate_scan

        # pdb.set_trace()

        dict_data = script_automate_scan()

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

    # if request.method == 'POST' and 'run_script_exploit' in request.POST:
    #
    #     data_table = request.POST.get('scan-table')
    #     print(data_table)
    #     print(type(data_table))
    #
    #     return render(request, 'dashboard/home/exploitcrafter_port_console.html',
    #                   {'flag_success_scan': flag_success_scan,
    #                    'dict_data': dict_data})
    #     from automate import script_automate_exploit
    #     from json_data_processing_script import session_organised_exploit
    #
    #     client, sessions_created = script_automate_exploit(data_scan, client, console)
    #
    #     if sessions_created != -1:
    #
    #         # pdb.set_trace()
    #
    #         flag_success_exploit = "True"
    #
    #         data_exploit = session_organised_exploit(sessions_created)
    #
    #         return render(request, 'dashboard/home/exploitcrafter_port_console.html',
    #                       {'flag_success_scan': flag_success_scan,
    #                        'data_scan': data_scan,
    #                        'data_exploit': data_exploit,
    #                        'flag_success_exploit': flag_success_exploit,
    #                        'champ_de_l_id': champ_de_l_id})
    #     else:
    #         flag_error = "True"
    #         error = 'Any session was created'
    #         return render(request, 'dashboard/home/exploitcrafter_port_console.html', {flag_error: 'flag_error',
    #                                                                               'data_scan': data_scan,
    #                                                                               'flag_success_scan': flag_success_scan,
    #                                                                               error: 'error'})
    #
    # if champ_de_l_id.is_valid() and request.method == 'POST' and 'run_script_session' in request.POST:
    #
    #     id_session = request.POST.get('entry_str')
    #
    #     for exploit in data_exploit:
    #         if id_session in exploit:
    #             flag_good_id = "True"
    #
    #     if flag_good_id is not None:
    #         return render(request, 'dashboard/home/metasploit_console_prompt.html',
    #                       {'champ_du_prompt': champ_du_prompt})
    #
    #     else:
    #         flag_error = "True"
    #         error = 'Bad Id session'
    #         return render(request, 'dashboard/home/exploitcrafter_port_console.html', {flag_error: 'flag_error',
    #                                                                               'data_scan': data_scan,
    #                                                                               'flag_success_scan': flag_success_scan,
    #                                                                               'data_exploit': data_exploit,
    #                                                                               'flag_success_exploit': flag_success_exploit,
    #                                                                               'champ_de_l_id': champ_de_l_id,
    #                                                                               error: 'error'})
    #
    #     #######################################PROMPT COMMANDE###############################
    # if champ_du_prompt.is_valid() and request.method == 'POST' and 'run_cmd' in request.POST:
    #     from metasploit_script import main_run_prompt
    #
    #     cmd_wanted = request.POST.get('prompt_str')
    #
    #     output = main_run_prompt(cmd_wanted, client.sessions.session(str(id_session)))
    #
    #     # if cmd_wanted == 'exit':
    #     #     return render(request, 'dashboard/home/exploitcrafter_console.html', {})
    #
    #     return render(request, 'dashboard/home/metasploit_console_prompt.html', {'champ_du_prompt': champ_du_prompt,
    #                                                                              'output': output})

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
    from metasploit_script import main_connection

    # call function
    client, console = main_connection()

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

    if ip_de_la_cible.is_valid() and port_de_la_cible.is_valid() and nombre_de_paquet.is_valid() and request.method == 'POST' and 'run_script' in request.POST:
        # import function to run
        from extra_scripts import syn_flood_attack

        ip_target = request.POST.get('ip_flood_syn_target')
        port_target = request.POST.get('port_flood_syn_target')
        number_of_paquet = request.POST.get('paquet_flood_syn_target')


        syn_flood_attack(ip_target, port_target, number_of_paquet)
        return render(request, 'dashboard/home/syn_flood_console.html', {'ip_de_la_cible': ip_de_la_cible, 'port_de_la_cible': port_de_la_cible,
                                                                             'nombre_de_paquet': nombre_de_paquet})


    return render(request, 'dashboard/home/syn_flood_console.html', {'ip_de_la_cible': ip_de_la_cible, 'port_de_la_cible': port_de_la_cible,
                                                                             'nombre_de_paquet': nombre_de_paquet})
