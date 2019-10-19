#!/usr/bin/python

'''
# Author: Michael Stott
# Date: 10/19/19
#
# Command line tool for scanning urls for CRLF injection.
'''

from scanner import CrlfScanner

import click, validators

@click.group()
def main():
    click.echo("Command line tool for detecting CRLF injection.")

@main.command("scan")
@click.option("-u", "--urls",  help="Comma delimited urls.")
@click.option("-i", "--ifile", help="File of urls to scan, separated by newlines")
@click.option("-o", "--ofile", help="Output scan results to file.")
def scan(urls, ifile, ofile):
    """ Performs CRLF injection on the specified URLs.
    """
    scanner = CrlfScanner()
    target_urls = _parse_urls(urls, ifile)
    vuln_urls = []
    if not target_urls:
        click.echo("No input found! Terminating.")
        return
    click.echo("Beginning scan...")
    for url in target_urls:
        crlf_urls = scanner.generate_vuln_urls(url.strip())
        for crlf_url in crlf_urls:
            if scanner.scan(crlf_url):
                vuln_urls.append(crlf_url)
                click.echo("CRLF detected: {}".format(crlf_url))
            else:
                click.echo("No CRLF detected: {}".format(crlf_url))
    click.echo("Finished scan!")
    if vuln_urls:
        click.echo("CRLF injection detected at the following URLs:")
        for vuln_url in vuln_urls:
            click.echo(vuln_url)
        if ofile:
            with open(outputfile, 'a') as out:
                for vuln_url in vuln_urls:
                    out.write(vuln_url)
                click.echo("Results saved to {}".format(ofile))
    else:
        click.echo("No CRLF injection detected...")

def _parse_urls(urls, ifile):
    """ Parses URLs from CLI args and input file.
    """
    target_urls = []
    # Parse the URLs.
    if urls:
        target_urls.extend([_clean(url) for url in urls.split(",")])
    if ifile:
        with open(ifile) as fp:
            for line in fp:
                target_urls.append(_clean(line))
    # Remove all nonvalid URLs.
    for target_url in target_urls:
        if not validators.domain(target_url):
            click.echo("Invalid URL: {}, Skipping...".format(target_url))
            target_urls.remove(target_url)
    return target_urls

def _clean(url):
    for protocol in CrlfScanner.PROTOCOL_LIST:
        if protocol + "://"  in url:
            url = url.replace(protocol + "://", "")
    url = url.strip()
    return url
                    
if __name__ == "__main__":
    main()
