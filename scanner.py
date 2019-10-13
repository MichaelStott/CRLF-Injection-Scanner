#!/usr/bin/python

'''
# Author: Michael Stott
# Date: 11/11/19
#
# Command line tool for scanning urls for CRLF injection.
'''

import eventlet, requests


class CrlfScanner():

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

    def __init__(self):
        self.inj_str = DEFAULT_INJ

    # Scan the url for crlf.
    def scan(self, url):
        # Store successful clrf attempts in buffer.
        buffer = []
        for append in self.APPEND_LIST:
            for escape in self.ESCAPE_LIST:
                crlf_url = url + append + escape + self.inj_str
                session = requests.Session()
                with eventlet.Timeout(self.TIMEOUT):
                    try:
                        session.get(crlf_url)
                        print(colored(crlf_url, 'magenta'))
                    except:
                        print(colored("Error: %s" % crlf_url, 'red'))
                    if 'param' in session.cookies.get_dict() and\
                        'crlf' in session.cookies.get_dict().values():
                        buffer.append(crlf_url)
        return buffer
