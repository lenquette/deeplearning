from django.shortcuts import render
from .forms import Input_for_Test, Formulaire_entree, Selection_entree, Checkbox_args_entree, \
    Formulaire_entree_search_metasploit, Formulaire_entree_run_metasploit, Formulaire_entree_options_metasploit, \
    Formulaire_entree_options_arg_metasploit, Formulaire_entree_payload_metasploit, Type_var_metasploit, \
    Formulaire_entree_prompt_metasploit, Type_var_payload_metasploit, Formulaire_entree_payload_option_metasploit, \
    Formulaire_entree_payload_option_val_metasploit, Choice_module

import sys
import os

# add executables' folder path
ProjectFileDir = os.path.dirname(os.path.abspath(__file__))
DashboardScriptDir = os.path.join(ProjectFileDir, 'static/script/')
sys.path.append(DashboardScriptDir)

# Create your views here.

def home_page(request):
    return render(request, 'dashboard/home/home.html', {})


def apropos(request):
    return render(request, 'dashboard/home/apropos.html', {})


def external(request):
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


def nmap_visu(request):

    #save data module
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


def metasploit_visu(request):
    # creation of flag
    global flag_connection
    global flag_search
    global flag_run
    global flag_option
    global flag_payload
    global flag_error
    global flag_auxiliary_ready_to_run
    global flag_choice

    # global var
    global module_choice

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
        data = main_connection()

        if data is not None:
            flag_connection = "connected"

        # renderer
        return render(request, 'dashboard/home/metasploit_console.html',
                      {'flag_connection': flag_connection, 'champ_de_recherche': champ_de_recherche,
                       'type_module': type_module})

    ##############################PRE-SELECTION MODULE'S TYPE ###############################
    if request.method == 'POST' and 'run_display_module' in request.POST:

        # checked pseudo~~~flag
        flag_choice = "True"
        # test section

        # call function
        module_choice = request.POST.get('module_wanted')

        print(module_choice)

        if module_choice == "EXPLOIT":
            from metasploit_script import main_display_exploit

            list_of_module = main_display_exploit()

        elif module_choice == "AUXILIARY":
            from metasploit_script import main_display_auxiliary

            list_of_module = main_display_auxiliary()

        # renderer
        return render(request, 'dashboard/home/metasploit_console.html',
                      {'flag_connection': flag_connection, 'list_of_module': list_of_module,
                       'champ_de_recherche': champ_de_recherche, 'type_module': type_module,
                       'flag_choice': flag_choice})

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
            list_of_exploit = main_display_exploit()

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
                           'flag_choice': flag_choice})

        ######################################AUXILIARY SECTION##################################
        elif module_choice == "AUXILIARY":

            from metasploit_script import main_display_auxiliary

            word_wanted = request.POST.get('search_str')

            # checked pseudo~~~flag
            flag_search = "True"

            # test section

            # call function
            list_of_auxiliary = main_display_auxiliary()

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
                           'flag_choice': flag_choice})

    #######################################CHOICE MODULE IN LIST###############################
    if champ_de_recherche.is_valid() and champ_du_run.is_valid() and type_de_var.is_valid() and request.method == 'POST' and 'run_run' in request.POST:

        ######################################EXPLOIT SECTION####################################
        if module_choice == "EXPLOIT":

            from metasploit_script import main_run_exploit

            module_wanted = request.POST.get('run_str')

            module_run = main_run_exploit(module_wanted)

            print(module_run.description)
            print(module_wanted)

            if module_run == -1:
                # checked pseudo~~~flag
                flag_run = None

                return render(request, 'dashboard/home/metasploit_console.html',
                              {'flag_connection': flag_connection, 'new_list': new_list,
                               'champ_de_recherche': champ_de_recherche, 'flag_search': flag_search,
                               'champ_du_run': champ_du_run, 'type_module': type_module,
                               'flag_choice': flag_choice})

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
                               'flag_choice': flag_choice})

        ######################################AUXILIARY SECTION##################################
        elif module_choice == "AUXILIARY":

            from metasploit_script import main_run_auxiliary

            module_wanted = request.POST.get('run_str')

            module_run = main_run_auxiliary(module_wanted)

            if module_run == -1:
                # checked pseudo~~~flag
                flag_run = None

                return render(request, 'dashboard/home/metasploit_console.html',
                              {'flag_connection': flag_connection, 'new_list': new_list,
                               'champ_de_recherche': champ_de_recherche, 'flag_search': flag_search,
                               'champ_du_run': champ_du_run,
                               'type_module': type_module,
                               'flag_choice': flag_choice})

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
                               'flag_choice': flag_choice})

    #######################################CONFIG MODULE###############################
    if champ_de_recherche.is_valid() and champ_du_run.is_valid() and type_de_var.is_valid() and champ_de_l_option.is_valid() and request.method == 'POST' and 'run_option' in request.POST:

        ######################################EXPLOIT SECTION####################################
        if module_choice == "EXPLOIT":

            from metasploit_script import main_change_option_exploit, main_see_payload

            option_wanted = request.POST.get('option_str')
            option_arg_wanted = request.POST.get('option_arg_str')
            type_wanted_arg = request.POST.get('type_wanted')

            flag_option = None

            module_running_config = main_change_option_exploit(option_wanted, option_arg_wanted, type_wanted_arg)

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
                               'flag_choice': flag_choice})

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
                    module_targetpayload = main_see_payload()

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
                               'flag_choice': flag_choice})

        ######################################AUXILIARY SECTION####################################
        elif module_choice == "AUXILIARY":

            from metasploit_script import main_change_option_auxiliary

            option_wanted = request.POST.get('option_str')
            option_arg_wanted = request.POST.get('option_arg_str')
            type_wanted_arg = request.POST.get('type_wanted')

            module_running_config = main_change_option_auxiliary(option_wanted, option_arg_wanted, type_wanted_arg)

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
                               'flag_choice': flag_choice})

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
                               'flag_choice': flag_choice})

    #######################################PAYLOAD CHOICE###############################
    if champ_de_recherche.is_valid() and champ_du_run.is_valid() and type_de_var.is_valid() and champ_de_l_option.is_valid() and type_de_var_payload.is_valid() and champ_de_la_config_payload.is_valid() and champ_de_la_val_de_la_config_payload.is_valid() and request.method == 'POST' and 'run_payload_choice' in request.POST:
        from metasploit_script import main_choose_payload

        payload_wanted = request.POST.get('payload_str')

        payload_chosen = main_choose_payload(payload_wanted)

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
                           'flag_choice': flag_choice})

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
                           'flag_choice': flag_choice})

    #######################################CONFIG PAYLOAD###############################
    if champ_de_recherche.is_valid() and champ_du_run.is_valid() and type_de_var.is_valid() and champ_de_l_option.is_valid() and type_de_var_payload.is_valid() and champ_de_la_config_payload.is_valid() and champ_de_la_val_de_la_config_payload.is_valid() and request.method == 'POST' and 'run_payload_option' in request.POST:
        from metasploit_script import main_config_payload

        payload_option_arg = request.POST.get('payload_option_str')
        payload_option_val = request.POST.get('payload_option_value_str')
        payload_option_type = request.POST.get('type_payload_wanted')

        flag_payload_value = None

        payload_runoptions = main_config_payload(payload_option_arg, payload_option_val, payload_option_type)

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
                           'flag_choice': flag_choice})

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
                           'flag_choice': flag_choice})

    #######################################RUN EXPLOIT AND HACK###############################
    if champ_de_recherche.is_valid() and champ_du_run.is_valid() and type_de_var.is_valid() and champ_de_l_option.is_valid() and request.method == 'POST' and 'run_exploit' in request.POST:
        from metasploit_script import main_exe_exploit

        # checked pseudo~~~flag
        flag_error = "True"

        json_payload = main_exe_exploit()

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
                           'type_module': type_module,
                           'flag_choice': flag_choice})
        else:
            return render(request, 'dashboard/home/metasploit_console_prompt.html',
                          {'champ_du_prompt': champ_du_prompt})

    #######################################RUN AUXILIARY AND HACK###############################
    if champ_de_recherche.is_valid() and champ_du_run.is_valid() and type_de_var.is_valid() and champ_de_l_option.is_valid() and request.method == 'POST' and 'run_auxiliary' in request.POST:
        from metasploit_script import main_exe_auxiliary

        json = main_exe_auxiliary()

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
                       'flag_choice': flag_choice})

        else:
            return render(request, 'dashboard/home/metasploit_console_prompt.html',
                          {'champ_du_prompt': champ_du_prompt })

    #######################################PROMPT COMMANDE###############################
    if champ_du_prompt.is_valid() and request.method == 'POST' and 'run_cmd' in request.POST:
        from metasploit_script import main_run_prompt

        cmd_wanted = request.POST.get('prompt_str')

        output = main_run_prompt(cmd_wanted)

        return render(request, 'dashboard/home/metasploit_console_prompt.html', {'champ_du_prompt': champ_du_prompt,
                                                                                 'output': output})

    return render(request, 'dashboard/home/metasploit_console.html', {})
