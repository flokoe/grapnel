#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
A simple, general purpose webhook service which executes local commands.

License: MIT (see LICENSE for details)
"""

from bottle import error, post, request, run
import subprocess, json

__author__ = 'Florian Köhler'
__version__ = '0.0.1'
__license__ = 'MIT'

def exec_command():
    command = ['id']
    subprocess.run(command)

@error(404)
def error404(error):
    return 'Pretty empty, huh...'

@post('/payload')
def payload():
    f = open("request_data.txt", "w")

    for item in request.headers:
        f.write(f"{item}: {request.headers.get(item)}\n")

    f.write("\n")
    f.write(json.dumps(request.json, indent=4, sort_keys=True))
    f.write("\n\n")
    f.close()

run(host='localhost', port=8090, reloader=True)
