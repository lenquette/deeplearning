import sys
import datetime

def main(name) :
	'''

	@param name: string of a name
	@return: string of the name with the current date
	'''
	time=datetime.datetime.now()
	output='Hi '+str(name)+' current time is '+str(time)
	return output
