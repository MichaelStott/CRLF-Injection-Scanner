# CRLF-Injection-Scanner

Command line tool for testing CRLF injection on a list of domains.

## Installation
```
$ python3 setup.py install
```

## Examples

Scan a target URL:

```
$ crlf scan -u "www.google.com"
```

Additionally, there is support for scanning URLs from a file, where URLs are separated by newlines.

```
$ crlf scan -i "urls.txt"
```
