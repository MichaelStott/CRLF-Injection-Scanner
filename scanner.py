#!/usr/bin/python

import eventlet, requests


class CrlfScanner():
    """ Scans URLs for CRLF injection.
    """

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
        self.inj_str = self.DEFAULT_INJ

    def generate_vuln_urls(self, url):
        """ Generate URLS that may be vulnerable to CRLF injection.
        """
        vuln_urls = []
        if not url.endswith('/'):
            url += '/'
        for protocol in self.PROTOCOL_LIST:
            for append in self.APPEND_LIST:
                for escape in self.ESCAPE_LIST:
                    vuln_urls.append(protocol + "://" + url +\
                                     append + escape + self.inj_str)
        return vuln_urls
    
    def scan(self, url):
        """ Scan target URL for CRLF injection
        """
        result = False
        session = requests.Session()
        with eventlet.Timeout(self.TIMEOUT):
            try:
                session.get(url)
            except KeyboardInterrupt:
                raise
            except:
                pass
            if 'param' in session.cookies.get_dict() and\
                'crlf' in session.cookies.get_dict().values():
                result = True
        return result
