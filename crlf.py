#!/usr/bin/python

'''
# Author: Michael Stott
# Date: 11/11/19
#
# Command line tool for scanning urls for CRLF injection.
'''

#import sys, getopt
#from termcolor import colored
import click

@click.command()
def main():
    click.echo("Command line tool for detecting CRL injection.")

if __name__ == "__main__":
    main()
    
"""
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
"""
