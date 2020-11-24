#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A simple, general purpose webhook service which executes local commands.

License: MIT (see LICENSE for details)
"""

import sys, functools, hmac, hashlib, subprocess
from bottle import default_app, error, post, request, run, HTTPError

__author__  = 'Florian Köhler'
__version__ = '0.2.0'
__license__ = 'MIT'

# Command Line Interface
def cli_parse(args):
    from argparse import ArgumentParser

    parser = ArgumentParser(usage="%(prog)s [options]")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("-b", "--bind", metavar="ADDRESS", type=str, help="bind service to ADDRESS (Default: localhost)")
    parser.add_argument("-p", "--port", type=int, help="bind service to PORT (Default: 8080)")
    parser.add_argument("-s", "--secret", type=str, help="secret for calculating 'X-Hub-Signature' and 'X-Hub-Signature-256' header or to use as a token in 'Authorization' header")
    parser.add_argument("-d", "--domain", type=str, help="domain/hostname which should be present in 'Host' header")
    parser.add_argument("-a", "--basicauth", type=str, help="basic auth credentials in form of 'user:password'")
    parser.add_argument("--no-auth", action="store_true", help="enables command execution without authorization header")
    parser.add_argument("-u", "--sudo-user", type=str, help="user that should be used by sudo")
    parser.add_argument("-c", dest="user_command", help="command and it's options that should be executed, needs to be ONE string")
    parser.add_argument("-f", "--config", type=str, help="location of config file (Default: /etc/hooked.ini)")

    return parser.parse_args(args[1:])

# Populate config withh options from defaults, conf file and cli args
def generate_config(args):
    c = default_app().config
    parsed_args = cli_parse(args)

    # Set hard coded defaults
    c['hooked.bind']    = 'localhost'
    c['hooked.port']    = 8080
    c['hooked.no_auth'] = False

    # Load config from file
    if parsed_args.config:
        c.load_config(parsed_args.config)
    else:
        c.load_config('/etc/hooked.ini')

    # Set arguments from cli if available
    if parsed_args.bind:
        c['hooked.bind'] = parsed_args.bind

    if parsed_args.port:
        c['hooked.port'] = parsed_args.port

    if parsed_args.secret:
        c['hooked.secret'] = parsed_args.secret

    if parsed_args.domain:
        c['hooked.domain'] = parsed_args.domain

    if parsed_args.basicauth:
        c['hooked.basicauth'] = parsed_args.basicauth

    if parsed_args.no_auth:
        c['hooked.no_auth'] = parsed_args.no_auth

    if parsed_args.sudo_user:
        c['hooked.sudo_user'] = parsed_args.sudo_user

    if parsed_args.user_command:
        c['hooked.user_command'] = parsed_args.user_command

# Check if user and password is valid
def is_authenticated_user(user, password):
    creds = conf['hooked.basicauth'].split(":")

    if user == creds[0] and password == creds[1]:
        print("Basic Auth was successful.")
        return True
    else:
        print("Wrong user or password.")
        return False

# Custom basic auth decorator
def my_basic_auth(check, realm="private", text="Access denied"):
    def decorator(func):

        @functools.wraps(func)
        def wrapper(*a, **ka):
            user, password = request.auth or (None, None)
            if 'hooked.basicauth' in conf:
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

def execute_command():
    print("execute...")

    sudo_args = ["sudo", "-u", conf['hooked.sudo_user']]

    subprocess.run(sudo_args + conf['hooked.user_command'].split())

def signature_check(header):
    if 'hooked.secret' not in conf:
        print(f"'{header}' found, but no secret is specified.")

    if header == 'Authorization':
        signature = request.headers.get(header).split()
        digest = conf['hooked.secret']
    else:
        signature = request.headers.get(header).split("=")

        def algo(al):
            if al == 'sha256':
                return hashlib.sha256
            else:
                return hashlib.sha1

        h = hmac.new(bytes(conf['hooked.secret'], 'utf-8'), request.body.read(), algo(signature[0]))
        digest = h.hexdigest()

    if signature[1] == digest:
        print(f"Authorized with {signature[0]}.")
        execute_command()
    else:
        print("Authorization failed.")

@error(404)
def error404(error):
    return 'Pretty empty, huh...'

@post('/payload')
@my_basic_auth(is_authenticated_user)
def payload():
    if 'X-Hub-Signature-256' in request.headers:
        signature_check('X-Hub-Signature-256')

    elif 'X-Hub-Signature' in request.headers:
        signature_check('X-Hub-Signature')

    elif 'Authorization' in request.headers:
        signature_check('Authorization')

    else:
        print("No authorization.")
        if conf['hooked.no_auth']:
            execute_command()


generate_config(sys.argv)
conf = default_app().config
run(server='bjoern', host=conf['hooked.bind'], port=conf['hooked.port'])
