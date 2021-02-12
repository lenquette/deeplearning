from django.shortcuts import render
from .forms import Input_for_Test, Formulaire_entree, Selection_entree, Checkbox_args_entree, Formulaire_entree_search_metasploit, Formulaire_entree_run_metasploit

import sys

# add executables' folder path
sys.path.append('/home/ludovic/python3_stuff/test_website/dashboard/static/script/')

# Create your views here.

def home_page(request):
	return render(request,'dashboard/home/home.html',{})
	
def apropos(request):
	return render(request,'dashboard/home/apropos.html',{})
	
def external(request):
	form= Input_for_Test(request.POST)
	
	if form.is_valid():
		
		if request.method == 'POST' and 'run_script' in request.POST:

			# import function to run
			from test_script import main
			
			inp = request.POST.get('test_str')
			#test section
			#print(inp)

			# call function
			data = main(inp) 

			# renderer
			return render(request,'dashboard/home/test.html', {'form':form, 'data': data})
	
	return render(request,'dashboard/home/test.html',{'form': form})
	

def nmap_visu(request):

	type_scan= Selection_entree(request.POST)
	ip_cible= Formulaire_entree(request.POST)
	arguments= Checkbox_args_entree(request.POST)
	
	if type_scan.is_valid() and ip_cible.is_valid() and arguments.is_valid() :
		
		if request.method == 'POST' and 'run_script' in request.POST:

			# import function to run
			from nmap_script import main
			
			type_scan_val = request.POST.get('scan_wanted')
			ip_cible_val = request.POST.get('entry_str')
			arguments_val = request.POST.getlist('arguments_checkbox')
			
			
			#test section
			print(type_scan_val)
			print(ip_cible_val)
			print(arguments_val)
			
			# call function
			data = main(type_scan_val,ip_cible_val,arguments_val)

			#renderer
			return render(request,'dashboard/home/nmap_console.html', {'type_scan_val':type_scan_val, 'ip_cible_val':ip_cible_val, 'arguments_val':arguments_val, 'data': data})
	
	return render(request,'dashboard/home/nmap_console.html',{'type_scan':type_scan, 'ip_cible':ip_cible, 'arguments':arguments})
	
def metasploit_visu(request):

	#creation flag
	global flag_connection
	global flag_search

	list_of_exploit, data = None, None
	
	champ_de_recherche = Formulaire_entree_search_metasploit(request.POST)
	champ_du_run = Formulaire_entree_run_metasploit(request.POST)

	if request.method == 'POST' and 'run_script' in request.POST:

		# import function to run
		from metasploit_script import main_connection
		
		#test section

		# call function
		data = main_connection()
		
		if data != None :
			flag_connection = "connected"
		
		#renderer
		return render(request,'dashboard/home/metasploit_console.html', {'flag_connection': flag_connection, 'champ_de_recherche':champ_de_recherche})
		
	if request.method == 'POST' and 'run_script_second' in request.POST:
	
		from metasploit_script import main_display_exploit
		
		#checked pseudo~~~flag
		
		#test section

		# call function
		list_of_exploit = main_display_exploit()

		#renderer
		return render(request,'dashboard/home/metasploit_console.html', {'flag_connection': flag_connection, 'list_of_exploit': list_of_exploit, 'champ_de_recherche':champ_de_recherche})
		
	
	if champ_de_recherche.is_valid() :
	
		if request.method == 'POST' and 'run_search' in request.POST:
			
			from metasploit_script import main_display_exploit
			
			word_wanted = request.POST.get('search_str')
			
			#checked pseudo~~~flag
			flag_search = "True"
			
			#test section

			# call function
			list_of_exploit = main_display_exploit()
			
			#create new list
			new_list = []
			
			for i in range(0,len(list_of_exploit),1) :
					
				if word_wanted in list_of_exploit[i] :
					
					new_list.append(list_of_exploit[i])
					
			#render
			return render(request,'dashboard/home/metasploit_console.html', {'flag_connection': flag_connection, 'new_list': new_list, 'champ_de_recherche':champ_de_recherche, 'flag_search' : flag_search, 'champ_du_run' : champ_du_run})
			
	if champ_de_recherche.is_valid() and champ_du_run().is_valid():
	
		if request.method == 'POST' and 'run_run' in request.POST:
		
			from metasploit_script import main_run_exploit
		
			exploit_wanted = request.POST.get('run_str')
			
			# call function
			exploit_running, exploit_running_description = main_run_exploit(exploit_wanted)
			
			#render
			return render(	
			
			
	
	return render(request,'dashboard/home/metasploit_console.html',{})

