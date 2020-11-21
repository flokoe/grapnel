#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
A simple, general purpose webhook service which executes local commands.

License: MIT (see LICENSE for details)
"""

import sys, functools, hmac, hashlib, json
from bottle import error, post, auth_basic, request, run, HTTPError

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
    parser.add_argument("-s", "--secret", type=str, help="secret SECRET for calculating 'X-Hub-Signature-256' header (required if adapter is 'github')")
    parser.add_argument("-t", "--token", type=str, help="token for 'Authorization' header (optional and only if adapter is 'generic')")
    parser.add_argument("-d", "--domain", type=str, help="domain/hostname which should be present in 'Host' header")
    parser.add_argument("-u", "--userauth", type=str, help="basic auth credentials in form of 'user:password'")

    return parser.parse_args(args[1:])

# Bottle logic

def is_authenticated_user(user, password):
    creds = conf.userauth.split(":")

    if user == creds[0] and password == creds[1]:
        print("Basic Auth was successful.")
        return True
    else:
        print("Wrong user or password.")
        return False

def my_basic_auth(check, realm="private", text="Access denied"):
    def decorator(func):

        @functools.wraps(func)
        def wrapper(*a, **ka):
            user, password = request.auth or (None, None)
            if conf.userauth:
                if user is None or not check(user, password):
                    err = HTTPError(401, text)
                    err.add_header('WWW-Authenticate', 'Basic realm="%s"' % realm)
                    return err
                return func(*a, **ka)
            else:
                print("no auth required")
                return func(*a, **ka)

        return wrapper

    return decorator

@error(404)
def error404(error):
    return 'Pretty empty, huh...'

@post('/payload')
@my_basic_auth(is_authenticated_user)
def payload():
    if conf.adapter == 'github':
        if not conf.secret:
            print("Adapter is 'github', but no secret is specified.")
            print("Exiting.")
            sys.exit(1)

        signature_header = request.headers.get('X-Hub-Signature-256')
        github_hash = signature_header.split("=")

        h = hmac.new(bytes(conf.secret, 'utf-8'), request.body.read(), hashlib.sha256)
        local_hash = h.hexdigest()

        if github_hash[1] == local_hash:
            print("verifiziert")

if __name__ == '__main__':
    conf = _cli_parse(sys.argv)

    run(host=conf.bind, port=conf.port, reloader=True)
