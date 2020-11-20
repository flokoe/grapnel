#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
A simple, general purpose webhook service which executes local commands.

License: MIT (see LICENSE for details)
"""

from bottle import post, run
import subprocess

__author__ = 'Florian Köhler'
__version__ = '0.0.1'
__license__ = 'MIT'

def exec_command():
    command = ['echo', 'hello', 'world']
    subprocess.run(command)

@post('/payload')
def payload():
    exec_command()

run(host='localhost', port=8090, reloader=True)
