# Nessus Scrape
# =============
# Description:  Nessus Scan Results -> CSV
# Author:       Adam Hurm
# Date:         07/17/17
# This could break with Nessus updates, it works as of the above date
# Written in python 2.7

from bs4 import BeautifulSoup
import csv
import sys


print "|| Nessus Scrape ||"
print "Command line usage: python nessus_scrape.py inputfile [outputfile]\n"
print "If no outputfile is given, output will go to 'inputfile'.csv"
print "This script ONLY APPENDS, no data will be accidentally overwritten."
print "=" * 70 + "\n"


if len(sys.argv) >= 3: #given cmd line input and output
    file_name = sys.argv[1]
    file_name_save = sys.argv[2] + ".csv"
    
elif len(sys.argv) >= 2: #given cmd line input
    print "You did not provide an outputfile as a command line argument.\n"
    file_name = sys.argv[1]
    file_name_save = file_name + ".csv"
    
else: #not given any cmd line args
    print "You did not provide an inputfile as a command line argument.\n"
    file_name = raw_input("Please enter the file name: ")


try:
    with open(file_name, 'r') as myfile: #open file and parse with bs
        print "Analyzing file, this step may take a moment.\n"
        soup = BeautifulSoup(myfile, "html.parser")
        
except IOError as e: #catch bad file name
    if e.errno == 2:
        print "\n!! Invalid inputfile name. !!"
    elif e.errno == 13:
        print "\n!! Access denied, check your access rights"
        print "and make sure you do not have the file open. !!"
    print "\nExiting now."
    sys.exit(0)


print "Searching for IPs.\n" 
ip_list = soup.find_all('h2', {'class' : 'classsection'}) #find section headers


print "Beginning scan through IPs.\n"
written = False
for ip in ip_list: #iterate through sections
    print "\nChecking %s" % ip.text
    #vulnerability table for IP
    vuln_table_html = ip.findNextSibling('table').findNextSibling('table')
    #sort out high and critical
    hc_list_html = vuln_table_html.find_all('td', {'class' : 'classcell4'}) + \
               vuln_table_html.find_all('td', {'class' : 'classcell3'})


    for report in hc_list_html: #iterate through high and critical vulns
        print "Vulnerability found, adding to list."
        risk_level = report.text
        plugin_id = report.findNextSibling('td').text
        description = report.findNextSibling('td').findNextSibling('td').text
        
        try:
            with open(file_name_save, 'ab') as csvfile: #append to csv file
                writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
                writer.writerow([ip.text, risk_level, plugin_id, description])
                written = True
        except IOError as e: #catch bad file access
            print "\nUnable to save to file, exiting to avoid innaccuracy/crash."
            if e.errno == 13:
                print "\n!! Access denied, check your access rights"
                print "and make sure you do not have the file open. !!"
            sys.exit(0) 


        '''
        #uncomment this to write to txt file, keeping if someone needs in the future
        if risk_level == "High": #clean up tabs before writing
            risk_level += "\t"
        with open((file_name + ".txt"), "a") as txt_file: #append to txt file
            txt_file.write("%s\t%s\t%s\t%s\n" % (ip.text, risk_level, plugin_id, description))
        '''


if written: #provide helpful responses
    print "Process complete, wrote to file %s" % (file_name_save)
else:
    print "No high or critical vulnerabilities were found."
