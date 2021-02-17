from django import forms

#both are same but one is used only for the test, guess who
class Input_for_Test(forms.Form):

	test_str = forms.CharField(max_length=15, required=False) #label='test_str'

class Formulaire_entree(forms.Form):

	entry_str = forms.CharField(max_length=15, required=False) #label='entry_str'

class Formulaire_entree_search_metasploit(forms.Form):

	search_str = forms.CharField(max_length=30, required=False) #label='search_str'

class Formulaire_entree_run_metasploit(forms.Form):

	run_str = forms.CharField(max_length=70, required=False) #label='run_str'

class Formulaire_entree_options_metasploit(forms.Form):

	option_str = forms.CharField(max_length=30, required=False) #label='option_str'

class Formulaire_entree_options_arg_metasploit(forms.Form):

	option_arg_str = forms.CharField(max_length=70, required=False) #label='option_arg_str'

class Formulaire_entree_payload_metasploit(forms.Form):

	payload_str = forms.CharField(max_length=70, required=False) #label='payload_str'

class Formulaire_entree_payload_option_metasploit(forms.Form):

	payload_option_str =  forms.CharField(max_length=70, required=False) #label='payload_str'

class Formulaire_entree_payload_option_val_metasploit(forms.Form):

	payload_option_value_str =  forms.CharField(max_length=70, required=False) #label='payload_str'

class Formulaire_entree_prompt_metasploit(forms.Form):

	prompt_str = forms.CharField(max_length=80, required=False) #label='payload_str'



#radio_select widget

class Selection_entree(forms.Form):

	SCAN_CHOICES = (
		('TCP', 'TCP'),
		('SYN', 'SYN'),
		('UDP', 'UDP'),
		('VERSION', 'VERSION'),
		)

	scan_wanted = forms.ChoiceField(choices=SCAN_CHOICES, widget=forms.RadioSelect(attrs={'class':'custom_radio_list'}), required=False)

class Type_var_metasploit(forms.Form):

	SCAN_CHOICES = (
		('INT', 'INT'),
		('BOOL', 'BOOL'),
		('STR', 'STR')
		)

	type_wanted = forms.ChoiceField(choices=SCAN_CHOICES, widget=forms.RadioSelect(), required=False)

class Type_var_payload_metasploit(forms.Form):

	SCAN_CHOICES = (
		('INT', 'INT'),
		('BOOL', 'BOOL'),
		('STR', 'STR')
		)

	type_payload_wanted = forms.ChoiceField(choices=SCAN_CHOICES, widget=forms.RadioSelect(), required=False)



class Checkbox_args_entree(forms.Form):

	ARGUMENTS = (
		('v4' , 'IPv4'),
		)

	arguments_checkbox = forms.MultipleChoiceField(choices=ARGUMENTS, widget=forms.CheckboxSelectMultiple(attrs={'class':'custom_checkbox'}), required=False)


