import nmap3

nmap = nmap3.NmapScanTechniques()
nmap_version = nmap3.Nmap()

def scan_nmap(type_scan, ip, list_of_args) :

	result = None
		
	if len(list_of_args) != 0 :
		if 'v4' in list_of_args :
			if type_scan == 'TCP':
				
				result = nmap.nmap_tcp_scan(ip, args="-v4")

			elif type_scan == 'SYN':
			
				result = nmap.nmap_syn_scan(ip, args="-v4")
							
			elif type_scan == 'UDP':
			
				result = nmap.nmap_udp_scan(ip, args="-v4")
				
			elif type_scan == 'VERSION':
			
				result =  nmap_version.nmap_version_detection(ip)
			
			else :
			
				return(-1)
		
		return result
	
	else :
		if type_scan == 'TCP':
			
			result = nmap.nmap_tcp_scan(ip)
		
		elif type_scan == 'SYN':
		
			result = nmap.nmap_syn_scan(ip)
			
		elif type_scan == 'UDP':
		
			result = nmap.nmap_udp_scan(ip)
			
		elif type_scan == 'VERSION':
				
			result =  nmap_version.nmap_version_detection(ip)
			
		else :
		
			return(-1)
		
		return result
		

def main(type_scan, ip, list_of_args) :

	result = scan_nmap(type_scan, ip, list_of_args)
	
	return result
