#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
A simple, general purpose webhook service which executes local commands.

License: MIT (see LICENSE for details)
"""

import sys
from bottle import error, post, request, run

__author__  = 'Florian Köhler'
__version__ = '0.0.1'
__license__ = 'MIT'

# Command Line Interface
def _cli_parse(args):
    from argparse import ArgumentParser

    parser = ArgumentParser(usage="%(prog)s [options]")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("-b", "--bind", metavar="ADDRESS", default="localhost", type=str, help="bind service to ADDRESS (Default: localhost)")
    parser.add_argument("-p", "--port", default=8080, type=int, help="bind service to PORT (Default: 8080)")
    parser.add_argument("-a", "--adapter", default="github", type=str, help="use adapter ADAPTER. Currently 'github' (default) and 'generic'")
    parser.add_argument("-s", "--secret", type=str, help="secret SECRET for calculating 'X-Hub-Signature-256' header (only if adapter is 'github')")
    parser.add_argument("-t", "--token", type=str, help="token for 'Authorization' header (only if adapter is 'generic')")
    parser.add_argument("-d", "--domain", type=str, help="domain/hostname which should be present in 'Host' header")
    parser.add_argument("-u", "--userauth", type=str, help="basic auth credentials in form of 'user:password'")

    return parser.parse_args(args[1:])

# Bottle logic
# def exec_command():
#     command = ['id']
#     subprocess.run(command)

@error(404)
def error404(error):
    return 'Pretty empty, huh...'

@post('/payload')
def payload():
    print('hello')

if __name__ == '__main__':
    conf = _cli_parse(sys.argv)

    run(host=conf.bind, port=conf.port, reloader=True)
