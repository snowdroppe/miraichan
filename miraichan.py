#!/usr/bin/env python3
import os
import sys
import signal
import threading
import argparse
import requests
from itertools import product

buffer_size = 10  # Input buffer size of worker (bytes)
debug = True    # Be very verbose about packet requests / responses
proxies = None  # Passed to requests as-is
headers = {
        "Cookie": None,
        "User-Agent": "python/2.7"
        }


"""
timeout /host /port
    -host is down
rejection /host /port
    -packet rejected
    -non http response
noauth
    -fail precheck i.e. no WWW-Authenticate header
fail /host /port /path /cred
    -bad creds i.e. 401 with creds
    -contains fail string
success
    -contains success string
    -break on success
"""

class _TimeoutError(Exception):
    pass

class _RejectionError(Exception):
    pass

class _FailError(Exception):
    pass

class _NoAuthError(Exception):
    pass

class FileMutex:
    def __init__(self, file, mutex):
        self.file = file
        self.mutex = mutex

class SmartGet:
    def __init__(self, args):
        self.timeout = args.timeout
        self.verify = not args.insecure
        self.skip = args.no_precheck
        self.success = args.success
        self.fail = args.fail
        self.headers = headers
        self.proxies = proxies
    
    def run(self, url, creds):
        try:
            if (not self.skip):
                # Perform precheck for www-authenticate header
                if (debug):
                    print("="*10 + url + "="*10)
                r = requests.get(url=url, auth=None, timeout=self.timeout,
                                 proxies=self.proxies, headers=self.headers,
                                 verify=self.verify)
                if(debug):
                    print("python --> server")
                    print(r.request.headers)
                    print("python <-- server")
                    print(r.headers)
                if ('www-authenticate' not in r.headers.keys()):
                    raise _NoAuthError
        except requests.exceptions.ConnectionError as e:
            if ("Connection refused" in str(e)):
                raise _RejectionError
            elif ("Failed to resolve" in str(e)):
                raise _TimeoutError
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout):
            raise _TimeoutError
        except requests.exceptions.SSLError:
            raise _FailError  # HTTPS request on HTTP listener
        except Exception as e:
            if (debug):
                raise e
            raise _FailError    # Hail mary

        for c in creds:
            c = tuple(c)
            try:
                r = requests.get(url=url, auth=c, timeout=self.timeout,
                                 proxies=self.proxies, headers=self.headers,
                                 verify=self.verify)
                if (debug):
                    print("python --> server")
                    print(r.request.headers)
                    print("python <-- server")
                    print(r.headers)
                # There is an edge case where redirection to a different domain
                # causes the Authorization header to be dropped. This is by design
                # so we work around this by retrying when redirected.
                # See https://github.com/psf/requests/issues/2949 and CVE-2014-1829
                if (r.history != []):
                    # Update url to follow final redirection
                    if (debug):
                        print("---- REDIRECTING [%d] ----" % (len(r.history),))
                    url = r.request.url
                    r = requests.get(url=url, auth=c, timeout=self.timeout,
                                     proxies=self.proxies, headers=self.headers,
                                     verify=self.verify)
                    if(debug):
                        print("python --> server")
                        print(r.request.headers)
                        print("python <-- server")
                        print(r.headers)


                if (r.status_code == 401):
                    continue
                elif (self.fail and self.fail in r.text):
                    continue
                elif (self.success and self.success not in r.text):
                    continue
                else:
                    return c    # Success!

            # TODO spend more time exhausting possible exceptions
            except requests.exceptions.ConnectionError as e:
                if ("Connection refused" in str(e)):
                    raise _RejectionError
                elif ("Failed to resolve" in str(e)):
                    raise _TimeoutError
            except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout):
                raise _TimeoutError
            except requests.exceptions.SSLError:
                raise _FailError  # HTTPS request on HTTP listener
            except Exception as e:
                if (debug):
                    raise e
                raise _FailError    # Hail mary

        raise _FailError  # Exhausted all creds

def sigint_handler(signal):
    pass


def worker(t_fm, o_fm, schemes, paths, creds):
    def pull(t_fm):
        with t_fm.mutex:
            targets = t_fm.file.readlines(buffer_size) 
        if (targets == []):
            return None
        # Clean up any whitespace and naughty characters (dirty but quick)
        targets = [(i.replace("\n", "").replace(" ", "").replace("\t", "")
                    .replace(":", "").replace(",", "")) for i in targets]
        return targets

    def push(o_fm, buf):
        with o_fm.mutex:
            o_fm.file.write("\n".join(buf)+"\n")

    smart = SmartGet(args)

    while(True):
        targets = pull(t_fm)
        # Aggregate logs together so we can write once
        buf = []
        if (targets == None):
            break
        for t in targets:
            for s in schemes:
                for p in paths:
                    url = "%s://%s:%d%s" % (s[0], t, s[1], p)
                    try:
                        r = smart.run(url, creds)
                        buf.append("success,%s,%s,%d,%s" % (s[0], t, s[1], p))
                    except _FailError:
                        buf.append("fail,%s,%s,%d,%s" % (s[0], t, s[1], p))
                    except _NoAuthError:
                        buf.append("noauth,%s,%s,%d,%s" % (s[0], t, s[1], p))
                    except _RejectionError:
                        buf.append("rejected,%s,%s,%d,%s" % (s[0], t, s[1], ""))
                        break   # Give up and try next scheme
                    except _TimeoutError:
                        buf.append("timeout,%s,%s,%d,%s" % (s[0], t, s[1], ""))
                        break   # Give up and try next scheme
        push(o_fm, buf)


def main(args):
    # TODO catch and handle sigint
    print("")
    # Calculate protocol:port pairs
    if (not args.ports):
        if (args.tls):
            schemes = [["https",443]]
        elif (args.no_tls):
            schemes = [["http",80]]
        else:
            schemes = [["http",80], ["https",443]]
    else:
        if (args.tls):
            proto = ["https"]
        elif (args.no_tls):
            proto = ["https"]
        else:
            proto = ["http", "https"]
        schemes = product(proto, ports)

    # Calculate credential pairs
    usernames, passwords = None, None
    if (args.logins):
        with open(args.logins, "r") as f:
            usernames = f.readlines()
            usernames = [i.replace("\n", "") for i in usernames]
    if (args.passwords):
        with open(args.passwords, "r") as f:
            passwords = f.readlines()
            passwords = [i.replace("\n", "") for i in passwords]

    if (usernames and passwords):
        if (args.clusterbomb):
            creds = product(usernames, passwords)
        else:
            if (len(usernames) != len(passwords)):
                raise IndexError("Dissimilar sized username and password"
                                 "lists cannot be used with pitchfork")
            creds = [list(i) for i in zip(usernames, passwords)]
    elif (usernames):
        creds = product(usernames, [args.password])
    elif (passwords):
        creds = product([args.login], passwords)
    else:
        creds = [[args.login, args.password]]

    t_fm = FileMutex(open(args.targets, "r"), threading.Lock())
    o_fm = FileMutex(open(args.outfile, "w"), threading.Lock())
    threads = []
    for i in range(args.threads):
        t = threading.Thread(target=worker, args=(t_fm, o_fm, schemes, args.paths, creds))
        threads.append(t)
    if (debug):
        print(t)
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    t_fm.file.close()
    o_fm.file_close()
    print("Woooooooo coffee break :D")


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
    main(args)
