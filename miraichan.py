#!/usr/bin/env python3
import os
import sys
import signal
import threading
import argparse
import requests
from itertools import product

proxy = None    # Passed as is to requests context
user_string = ' '   # User agent string
cookie = None   # Cookie to use during requests
retries = 3   # Number of retries to attempt before timing out
page_size = 10  # How many targets a worker should grab 
debug = True    # Be very verbose about packet requests / responses

"""
timeout /host /port
    -host is down
rejection /host /port
    -packet rejected
    -non http response
fail /host /port /path /cred
    -fail precheck i.e. no WWW-Authenticate header
    -bad creds i.e. 401 with creds
    -contains fail string
success
    -contains success string
    -break on success
"""

class TimeoutError(Exception):
    pass

class RejectionError(Exception):
    pass

class FailError(Exception):
    pass

class SmartGet:
    def __init__(self, args):
        self.verify = not args.insecure
        self.skip = args.no_precheck
        self.headers = headers
        self.success = args.success
        self.fail = args.fail
    
    def brute(self, url, creds):
        try:
            if (not self.skip):
                # Perform precheck for www-authenticate header
                r = requests.get(url=url, auth=None,
                                 headers=self.headers, verify=self.insecure)
                if ('www-authenticate' not in r.headers.keys()):
                    raise FailError
        except Exception:   # TODO handle exceptions
            pass

        for c in creds:
            try:
                r = requests.get(url=url, auth=c,
                                 headers=self.headers, verify=self.insecure)
                # There is an edge case where redirection to a different domain
                # causes the Authorization header to be dropped. This is by design
                # so we work around this by retrying when redirected.
                # See https://github.com/psf/requests/issues/2949 and CVE-2014-1829
                if (r.history != []):
                    # Update url to follow final redirection
                    url = r.requests.url
                    r = requests.get(url=url, auth=c,
                                     headers=self.headers, verify=self.insecure)

                if (r.status_code == 401):
                    continue
                elif (self.fail and self.fail in r.text):
                    continue
                elif (self.success and self.success not in r.text):
                    continue
                else:
                    return c    # Success!


            except Exception: # TODO handle excpetions
                pass
        raise FailError  # Exhausted all creds

def sigint_handler(signal):
    pass


def worker(mutex_in, fd_in, mutex_out, fd_out):
    smart = SmartGet(args)
    #for t in targets:
    #    for p in ports:

def main(args):
    # Calculate protocol:port pairs
    if (not args.ports):
        if (args.tls):
            schemes = [["https://",443]]
        elif (args.no_tls):
            schemes = [["http://",80]]
        else:
            schemes = [["http://",80], ["https://",443]]
    else:
        if (args.tls):
            proto = ["https://"]
        elif (args.no_tls):
            proto = ["https://"]
        else:
            proto = ["http://", "https://"]
        schemes = product(proto, ports)
    # Calculate credential pairs
    if (args.clusterbomb):
        creds = product(usernames, passwords)
    else:
        if (len(usernames) != len(passwords)):
            raise IndexError("Dissimilar sized username and password"
                             "lists cannot be used with pitchfork")
        creds = [list(i) for i in zip(usernames, passwords)]
    # TODO catch and handle sigint
    # TODO open file handles
    # TODO spawn workers



if (__name__ == "__main__"):
    parser = argparse.ArgumentParser(
            description="Python based basic auth scanner",
            usage="%(prog)s [options] (-l user | -L file) (-p pass | -P file) -o outfile targets")
    parser.add_argument("targets", help="filename containing targets (IPs / hostnames)")
    parser.add_argument("-o", "--outfile", metavar="file",
                        required=True, help="filename for output csv file")

    # Trying to be consistent with hydra :)
    group1 = parser.add_mutually_exclusive_group(required=True)
    group2 = parser.add_mutually_exclusive_group(required=True)
    group1.add_argument("-l", "--login", metavar="USER",
                            help="username to use for auth")
    group2.add_argument("-p", "--password", metavar="PASS",
                            help="password to use for auth")
    group1.add_argument("-L", "--logins", metavar="FILE",
                            help="filename containing usernames to use for auth")
    group2.add_argument("-P", "--passwords", metavar="FILE",
                            help="filename containing passwords to use for auth")
    group3 = parser.add_mutually_exclusive_group()
    group3.add_argument("--pitchfork", action="store_true",
                            help="combine user/pass by line (default)")
    group3.add_argument("--clusterbomb", action="store_true",
                            help="combine user/pass by cartesian join")
    parser.add_argument("--paths", metavar="PATH", nargs="+", default=["/"],
                            help="URL path(s) to basic auth page (default = /)")

    group4 = parser.add_argument_group("success criteria")
    group4.add_argument("--no-precheck", action="store_true",
                        help="disable default precheck to ensure page serves basic auth")
    group4.add_argument("--success",  metavar="STRING", nargs="+",
                        help="response string required to qualify a success")
    group4.add_argument("--fail",  metavar="STRING", nargs="+",
                        help="response string sufficient to qualify a fail")

    group5 = parser.add_argument_group("connection",
                                       "defaults to attempt HTTP on 80 and HTTPS on 443")
    group6 = group5.add_mutually_exclusive_group()
    group6.add_argument("--no-tls", action="store_true", help="only attempt HTTP")
    group6.add_argument("--tls", action="store_true", help="only attempt HTTPS")
    group5.add_argument("--insecure", action="store_true",
                        help="disable TLS certificate verification")
    group5.add_argument("--ports", nargs="+", metavar="X", type=int,
                        help="port(s) to connect on (will be forced for chosen protocols)")
    group5.add_argument("--threads", type=int, default=10,
                        help="number of threads to spawn (default = 10)")
    group5.add_argument("--timeout", type=int, default=10,
                        help="seconds to timeout requests (default = 10)")
    
    group7 = parser.add_argument_group("batch control",
               ("can be used to resume interrupted sessions or "
               "distribute work across multiple instances"))
    group7.add_argument("--start", type=int, help="start line (inclusive)")
    group7.add_argument("--end", type=int, help="end line (inclusive)")

    args = parser.parse_args()
    print(args)
