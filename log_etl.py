"""
Linux Syslog Processor
Author: Aaron Liske
Date: 2022-05-28

Other Group Members: 
	Yogesh Chavarkar
	William Smith III
	Mia Jones

Written for EMU IA-645 Data Analytics for Cybersecurity

This file reads the linux syslog files searching for brute force or root entry through ftpd, ftp, samba, sshd, and rpc (buffer overflow attacks).

Output is a csv file with the following fields:
- Raw log line
- Working or non working day (weekends)
- General Time of day
- Process run
- EUID (if known)
- Suspicious log entry (TRUE/FALSE)
"""
import os
import re
import csv
from datetime import datetime
import calendar

#declare variables used.  Change directory for logs
directory = 'logs'

count = 1
prev_service = ''
prev_timestamp = ''
prev_host = ''

#define function for user types.  Can be expanded for others, if system needs.
def user_type(euid):
	if euid == "0":
		return "root"
	else:
		return "other"

#define function to parse the message, with the service as the main logic branch
#outputs the formatted string including the determined user level as well as the suspicion

#TODO: move user level to appropriate function for output instead of dual outputs for brevity
def message_parse(svc, msg, timestamp):
	#gain access to the variables needed
	global prev_service
	global prev_host
	global prev_timestamp

	#set variable defaults
	suspicious = 'false'
	user_level = 'no_euid'

	#because sshd and samba have such similar messages, processing is identical
	if svc == 'sshd' or svc == 'samba':
		m = re.search('^(.*?) (euid=)(\d+) (.*?)$', msg)
		if(m):
			user_level = user_type(m.group(3))
			if user_level == 'root':
				suspicious = 'true'
			else:
				suspicious = 'false'
		else:
			suspicious = 'false'

	#process log for ftp(d).  mark as suspicious if line matches previous entry's remote host or is within 2 seconds per timestamp
	if svc == 'ftpd' or svc == 'ftp':
		m = re.search(r"^(.*?)(\d+\.\d+\.\d+\.\d+)(.*?)$", msg.replace('\.','.'))
		curr_host = ''
		if(m):
			curr_host = m.group(2)
		if prev_service == 'ftpd' or prev_service == 'ftp':
			if prev_timestamp != '':
				#parse out the seconds for the timestamp
				#TODO: add logic for seconds under 2 to loop back to 59 for timestamp checking
				prev_seconds = int(prev_timestamp.split(":")[2])
				curr_seconds = int(timestamp.split(":")[2])
				delta_time = curr_seconds - prev_seconds
				if (curr_seconds - prev_seconds < 2 or curr_host == prev_host) and (msg.strip() != "FTP session closed"):
					suspicious = 'true'
				else:
					suspicious = 'false'
			#set host and timestamp variables for comparison later
			prev_host = curr_host
			prev_timestamp = timestamp
		else:
			suspicious = 'false'

	#all rpc calls with gethostbyname are suspicious for buffer overflow attacks
	if svc == "rpc":
		m = re.search('^(.*?)(gethostbyname)(.*?)$', msg)
		if(m):
			if m.group(2) == 'gethostbyname':
				suspicious = 'true'
			else:
				suspicious = 'false'
		else:
			suspicious = 'false'
	#set previous service variable for future comparison
	prev_service = svc
	return user_level + '\t|' + suspicious

#open csv file for writing
csvfile = open('data.csv','w', newline='')

writer = csv.writer(csvfile)

#loop through all directories for reading
for filename in os.listdir(directory):
	
	f = os.path.join(directory, filename)
	if os.path.isfile(f):
		print(f)
		file = open(f, "r")
		Lines = file.readlines()
		for line in Lines:
			#because the year is NOT in the log file lines, get from the filename, before the first period
			#this is for determining the day of the week
			year = filename.split(".",1)
			#regex the log file line
			m = re.search('^(\w\w\w\s+\d+) (\d\d:\d\d:\d\d) (.*?) (.*?)(\W)(.*?)(.*?)(\W)(.*?) (.*?)$', line.strip())
			if(m):
				date = m.group(1) + " " + year[0]
				#create a datetime object from the parsed date
				datetime_object = datetime.strptime(date, '%b %d %Y')
				#determine day of the week, and if weekend, set the day_type as "NON_WORKING"
				day_of_week = datetime_object.strftime('%A')
				if day_of_week == 'Sunday' or day_of_week == 'Saturday':
					day_type = 'NON_WORKING'
				else:
					day_type = 'WORKING'
				#parse out the hour to determine the time of day. This is simplified through the use of 24h time
				hour = int(m.group(2).split(":",1)[0])
				time_of_day = ""
				if hour >= 0 and hour <= 6:
					time_of_day = 'early morning'
				if hour >= 7 and hour <= 11:
					time_of_day = 'morning'
				if hour >= 12 and hour <=17:
					time_of_day = 'afternoon'
				if hour >= 18 and hour <= 21:
					time_of_day = 'evening'
				if hour > 21:
					time_of_day = 'night'

				#escape all special characters in the log message
				escaped = m.group(10).strip().translate(str.maketrans({"-":  r"\-",
                                      "]":  r"\]",
                                      "\\": r"\\",
                                      "^":  r"\^",
                                      "$":  r"\$",
                                      "*":  r"\*",
                                      ".":  r"\."}))
				#determine the suspicion level through defined function
				suspicion = message_parse(m.group(4).strip(), escaped, m.group(2))

				#console output of CSV file, minus the raw log line
				print("{}\t|{}\t|{}\t|\t{}\t\t|\t{}".format(count, day_type,  time_of_day, m.group(4), suspicion))
				suspicion_split = suspicion.split('\t|')

				#create array for CSV writer
				data = [m.group(0),day_type,time_of_day,m.group(4),suspicion_split[0],suspicion_split[1]]
				#write data to CSV file
				writer.writerow(data)
				#increase line count
				count+=1
		#close both files
		file.close()
csvfile.close()


