from django.shortcuts import render
from .forms import Input_for_Test, Formulaire_entree, Selection_entree, Checkbox_args_entree, \
    Formulaire_entree_search_metasploit, Formulaire_entree_run_metasploit, Formulaire_entree_options_metasploit, \
    Formulaire_entree_options_arg_metasploit, Formulaire_entree_payload_metasploit, Type_var_metasploit, \
    Formulaire_entree_prompt_metasploit, Type_var_payload_metasploit, Formulaire_entree_payload_option_metasploit, \
    Formulaire_entree_payload_option_val_metasploit

import sys

# add executables' folder path
sys.path.append('/home/ludovic/python3_stuff/test_website/dashboard/static/script/')


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
    type_scan = Selection_entree(request.POST)
    ip_cible = Formulaire_entree(request.POST)
    arguments = Checkbox_args_entree(request.POST)

    if type_scan.is_valid() and ip_cible.is_valid() and arguments.is_valid():

        if request.method == 'POST' and 'run_script' in request.POST:
            # import function to run
            from nmap_script import main

            type_scan_val = request.POST.get('scan_wanted')
            ip_cible_val = request.POST.get('entry_str')
            arguments_val = request.POST.getlist('arguments_checkbox')

            # test section
            # print(type_scan_val)
            # print(ip_cible_val)
            # print(arguments_val)

            # call function
            data = main(type_scan_val, ip_cible_val, arguments_val)

            # renderer
            return render(request, 'dashboard/home/nmap_console.html',
                          {'type_scan_val': type_scan_val, 'ip_cible_val': ip_cible_val, 'arguments_val': arguments_val,
                           'data': data})

    return render(request, 'dashboard/home/nmap_console.html',
                  {'type_scan': type_scan, 'ip_cible': ip_cible, 'arguments': arguments})


def metasploit_visu(request):
    # creation flag
    global flag_connection
    global flag_search
    global flag_run
    global flag_option
    global flag_payload
    global flag_payload_error

    # global var
    global list_of_exploit
    global new_list
    global exploit_run
    global exploit_description
    global exploit_options
    global exploit_missing_required
    global exploit_running_config
    global exploit_targetpayload
    global payload_chosen
    global payload_runoptions
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

    type_de_var = Type_var_metasploit(request.POST)
    type_de_var_payload = Type_var_metasploit(request.POST)

    champ_du_prompt = Formulaire_entree_prompt_metasploit(request.POST)

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
                      {'flag_connection': flag_connection, 'champ_de_recherche': champ_de_recherche})

    if request.method == 'POST' and 'run_script_second' in request.POST:
        from metasploit_script import main_display_exploit

        # checked pseudo~~~flag

        # test section

        # call function
        list_of_exploit = main_display_exploit()

        # renderer
        return render(request, 'dashboard/home/metasploit_console.html',
                      {'flag_connection': flag_connection, 'list_of_exploit': list_of_exploit,
                       'champ_de_recherche': champ_de_recherche})

    if champ_de_recherche.is_valid() and request.method == 'POST' and 'run_search' in request.POST:

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
                       'champ_du_run': champ_du_run})

    if champ_de_recherche.is_valid() and champ_du_run.is_valid() and type_de_var.is_valid() and request.method == 'POST' and 'run_run' in request.POST:
        from metasploit_script import main_run_exploit

        exploit_wanted = request.POST.get('run_str')

        exploit_run = main_run_exploit(exploit_wanted)

        if exploit_run == -1:
            # checked pseudo~~~flag
            flag_run = None

            return render(request, 'dashboard/home/metasploit_console.html',
                          {'flag_connection': flag_connection, 'new_list': new_list,
                           'champ_de_recherche': champ_de_recherche, 'flag_search': flag_search,
                           'champ_du_run': champ_du_run})

        else:
            # checked pseudo~~~flag
            flag_run = "True"

            exploit_description, exploit_options, exploit_missing_required, exploit_running_config, exploit_targetpayload = exploit_run.description, exploit_run.options, exploit_run.missing_required, exploit_run.runoptions, exploit_run.targetpayloads

            return render(request, 'dashboard/home/metasploit_console.html',
                          {'flag_connection': flag_connection, 'new_list': new_list,
                           'champ_de_recherche': champ_de_recherche, 'flag_search': flag_search,
                           'champ_du_run': champ_du_run, 'exploit_description': exploit_description,
                           'exploit_options': exploit_options, 'exploit_missing_required': exploit_missing_required,
                           'flag_run': flag_run, 'exploit_running_config': exploit_running_config,
                           'champ_de_l_option': champ_de_l_option,
                           'champ_de_l_arg_de_option': champ_de_l_arg_de_option, 'type_de_var': type_de_var})

    if champ_de_recherche.is_valid() and champ_du_run.is_valid() and type_de_var.is_valid() and champ_de_l_option.is_valid() and request.method == 'POST' and 'run_option' in request.POST:
        from metasploit_script import main_change_option, main_see_payload

        option_wanted = request.POST.get('option_str')
        option_arg_wanted = request.POST.get('option_arg_str')
        type_wanted_arg = request.POST.get('type_wanted')

        exploit_running_config = main_change_option(option_wanted, option_arg_wanted, type_wanted_arg)
        exploit_targetpayload = main_see_payload()

        flag_option = None

        # refresh data about the exploit
        if option_wanted in exploit_missing_required:
            exploit_missing_required.remove(option_wanted)

        # checked pseudo~~~flag
        if len(exploit_missing_required) == 0:
            #     # checked pseudo~~~flag
            flag_option = "True"

        return render(request, 'dashboard/home/metasploit_console.html',
                      {'flag_connection': flag_connection, 'new_list': new_list,
                       'champ_de_recherche': champ_de_recherche, 'flag_search': flag_search,
                       'champ_du_run': champ_du_run, 'exploit_description': exploit_description,
                       'exploit_options': exploit_options, 'flag_run': flag_run,
                       'exploit_missing_required': exploit_missing_required,
                       'exploit_running_config': exploit_running_config,
                       'champ_de_l_option': champ_de_l_option,
                       'champ_de_l_arg_de_option': champ_de_l_arg_de_option, 'flag_option': flag_option,
                       'type_de_var': type_de_var, 'exploit_targetpayload': exploit_targetpayload,
                       'champ_du_payload': champ_du_payload})

    if champ_de_recherche.is_valid() and champ_du_run.is_valid() and type_de_var.is_valid() and champ_de_l_option.is_valid() and type_de_var_payload.is_valid() and champ_de_la_config_payload.is_valid() and champ_de_la_val_de_la_config_payload.is_valid() and request.method == 'POST' and 'run_payload_choice' in request.POST:
        from metasploit_script import main_choose_payload

        payload_wanted = request.POST.get('payload_str')

        # checked pseudo~~~flag
        flag_payload = "True"

        payload_chosen = main_choose_payload(payload_wanted)
        payload_runoptions = payload_chosen.runoptions
        payload_missing_required = payload_chosen.missing_required

        return render(request, 'dashboard/home/metasploit_console.html',
                      {'flag_connection': flag_connection, 'new_list': new_list,
                       'champ_de_recherche': champ_de_recherche, 'flag_search': flag_search,
                       'champ_du_run': champ_du_run, 'exploit_description': exploit_description,
                       'exploit_options': exploit_options, 'flag_run': flag_run,
                       'exploit_missing_required': exploit_missing_required,
                       'exploit_running_config': exploit_running_config,
                       'champ_de_l_option': champ_de_l_option,
                       'champ_de_l_arg_de_option': champ_de_l_arg_de_option, 'flag_option': flag_option,
                       'type_de_var': type_de_var, 'exploit_targetpayload': exploit_targetpayload,
                       'champ_du_payload': champ_du_payload, 'payload_chosen': payload_chosen,
                       'champ_de_la_config_payload': champ_de_la_config_payload,
                       'champ_de_la_val_de_la_config_payload': champ_de_la_val_de_la_config_payload,
                       'payload_runoptions': payload_runoptions, 'payload_missing_required': payload_missing_required,
                       'type_de_var_payload': type_de_var_payload, 'flag_payload': flag_payload})

    if champ_de_recherche.is_valid() and champ_du_run.is_valid() and type_de_var.is_valid() and champ_de_l_option.is_valid() and type_de_var_payload.is_valid() and champ_de_la_config_payload.is_valid() and champ_de_la_val_de_la_config_payload.is_valid() and request.method == 'POST' and 'run_payload_option' in request.POST:
        from metasploit_script import main_config_payload

        payload_option_arg = request.POST.get('payload_option_str')
        payload_option_val = request.POST.get('payload_option_value_str')
        payload_option_type = request.POST.get('type_payload_wanted')

        payload_runoptions = main_config_payload(payload_option_arg, payload_option_val, payload_option_type)

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
                       'champ_du_run': champ_du_run, 'exploit_description': exploit_description,
                       'exploit_options': exploit_options, 'flag_run': flag_run,
                       'exploit_missing_required': exploit_missing_required,
                       'exploit_running_config': exploit_running_config,
                       'champ_de_l_option': champ_de_l_option,
                       'champ_de_l_arg_de_option': champ_de_l_arg_de_option, 'flag_option': flag_option,
                       'type_de_var': type_de_var, 'exploit_targetpayload': exploit_targetpayload,
                       'champ_du_payload': champ_du_payload, 'payload_chosen': payload_chosen,
                       'champ_de_la_config_payload': champ_de_la_config_payload,
                       'champ_de_la_val_de_la_config_payload': champ_de_la_val_de_la_config_payload,
                       'type_de_var_payload': type_de_var_payload, 'payload_runoptions': payload_runoptions,
                       'payload_missing_required': payload_missing_required,
                       'flag_payload': flag_payload, 'flag_payload_value': flag_payload_value})

    if champ_de_recherche.is_valid() and champ_du_run.is_valid() and type_de_var.is_valid() and champ_de_l_option.is_valid() and request.method == 'POST' and 'run_exploit' in request.POST:
        from metasploit_script import main_exe_exploit

        payload_wanted = request.POST.get('payload_str')

        # checked pseudo~~~flag
        flag_payload_error = "True"

        json_payload = main_exe_exploit()

        # json_payload = True

        if json_payload == -1:
            error = "Failed to create session"

            return render(request, 'dashboard/home/metasploit_console.html',
                          {'flag_connection': flag_connection, 'new_list': new_list,
                           'champ_de_recherche': champ_de_recherche, 'flag_search': flag_search,
                           'champ_du_run': champ_du_run, 'exploit_description': exploit_description,
                           'exploit_options': exploit_options, 'flag_run': flag_run,
                           'exploit_missing_required': exploit_missing_required,
                           'exploit_running_config': exploit_running_config,
                           'champ_de_l_option': champ_de_l_option,
                           'champ_de_l_arg_de_option': champ_de_l_arg_de_option, 'flag_option': flag_option,
                           'type_de_var': type_de_var, 'exploit_targetpayload': exploit_targetpayload,
                           'champ_du_payload': champ_du_payload, 'payload_chosen': payload_chosen,
                           'champ_de_la_config_payload': champ_de_la_config_payload,
                           'champ_de_la_val_de_la_config_payload': champ_de_la_val_de_la_config_payload,
                           'type_de_var_payload': type_de_var_payload, 'payload_runoptions': payload_runoptions,
                           'flag_payload': flag_payload, 'flag_payload_error': flag_payload_error})
        else:
            return render(request, 'dashboard/home/metasploit_console_prompt.html', {'champ_du_prompt': champ_du_prompt,
                                                                                     })

    if champ_du_prompt.is_valid() and request.method == 'POST' and 'run_cmd' in request.POST:
        from metasploit_script import main_run_prompt

        cmd_wanted = request.POST.get('prompt_str')

        output = main_run_prompt(cmd_wanted)

        return render(request, 'dashboard/home/metasploit_console_prompt.html', {'champ_du_prompt': champ_du_prompt,
                                                                                 'output': output})

    return render(request, 'dashboard/home/metasploit_console.html', {})
