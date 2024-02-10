#!/usr/bin/env python3
import os
import sys
import signal
import threading
import argparse
import requests

proxy = None    # Passed as is to requests context
user_string = ' '   # User agent string
page_size = 10  # How many targets a worker should grab 
debug = True    # Be very verbose about packet requests / responses


def sigint_handler(signal):
    pass


def worker(mutex_in, fd_in, mutex_out, fd_out):
    pass


def main(args):
    pass


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
    group1.add_argument("-l", "--login", metavar="user",
                        help="username to use for auth")
    group2.add_argument("-p", "--password", metavar="pass",
                        help="password to use for auth")
    group1.add_argument("-L", "--logins", metavar="file",
                        help="filename containing usernames to use for auth")
    group2.add_argument("-P", "--passwords", metavar="file",
                        help="filename containing passwords to use for auth")

    group3 = parser.add_argument_group("connection",
                                       "defaults to attempt HTTP on 80 and HTTPS on 443")
    group4 = group3.add_mutually_exclusive_group()
    group4.add_argument("--no-tls", action="store_true", help="only attempt HTTP")
    group4.add_argument("--tls", action="store_true", help="only attempt HTTPS")

    group3.add_argument("--ports", nargs="+", metavar="X", type=int,
                        help="port(s) to connect on (will be forced for chosen protocols)")
    group3.add_argument("--threads", type=int, default=10,
                        help="number of threads to spawn (default = 10)")
    group3.add_argument("--timeout", type=int, default=10,
                        help="seconds to timeout requests (default = 10)")
    
    group5 = parser.add_argument_group("batch control",
               ("can be used to resume interrupted sessions or "
               "distribute work across multiple instances"))
    group5.add_argument("--start", type=int, help="start line (inclusive)")
    group5.add_argument("--end", type=int, help="end line (inclusive)")

    args = parser.parse_args()
    print(args)
