import sys
import datetime

def main(name) :
	time=datetime.datetime.now()
	output='Hi '+str(name)+' current time is '+str(time)
	#print(output)
	return output
