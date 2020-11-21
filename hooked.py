#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
A simple, general purpose webhook service which executes local commands.

License: MIT (see LICENSE for details)
"""

import sys, functools, hmac, hashlib
from bottle import error, post, request, run, HTTPError

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
    parser.add_argument("-s", "--secret", type=str, help="secret for calculating 'X-Hub-Signature' and 'X-Hub-Signature-256' header or to use as a token in 'Authorization' header")
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
                print("No basic auth required.")
                return func(*a, **ka)

        return wrapper

    return decorator

def signature_check(header):
    if not conf.secret:
        print(f"'{header}' found, but no secret is specified.")

    if header == 'Authorization':
        signature = request.headers.get(header).split()
        local_hash = conf.secret
    else:
        signature = request.headers.get(header).split("=")

        def algo(al):
            if al == 'sha256':
                return hashlib.sha256
            else:
                return hashlib.sha1

        h = hmac.new(bytes(conf.secret, 'utf-8'), request.body.read(), algo(signature[0]))
        local_hash = h.hexdigest()

    if signature[1] == local_hash:
        print(f"Authorized with {signature[0]}.")
    else:
        print("Authorization failed.")

@error(404)
def error404(error):
    return 'Pretty empty, huh...'

@post('/payload')
@my_basic_auth(is_authenticated_user)
def payload():
    if request.headers.get('X-Hub-Signature-256'):
        signature_check('X-Hub-Signature-256')

    elif request.headers.get('X-Hub-Signature'):
        signature_check('X-Hub-Signature')

    elif request.headers.get('Authorization'):
        signature_check('Authorization')

    else:
        print("No authorization.")

if __name__ == '__main__':
    conf = _cli_parse(sys.argv)

    run(host=conf.bind, port=conf.port, reloader=True)
