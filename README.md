# hooked

A simple, general purpose webhook service which executes local commands via sudo.

## Requirements

- [bjoern](https://github.com/jonashaag/bjoern)
- python `requests` library

## Usage

```plain
usage: hooked.py [options]

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -b ADDRESS, --bind ADDRESS
                        bind service to ADDRESS (Default: localhost)
  -p PORT, --port PORT  bind service to PORT (Default: 8080)
  -s SECRET, --secret SECRET
                        secret for calculating 'X-Hub-Signature' and 'X-Hub-Signature-256' header or to use as a token in 'Authorization' header
  -d DOMAIN, --domain DOMAIN
                        domain/hostname which should be present in 'Host' header
  -a BASICAUTH, --basicauth BASICAUTH
                        basic auth credentials in form of 'user:password'
  --no-auth             enables command execution without authorization header
  -u SUDO_USER, --sudo-user SUDO_USER
                        user that should be used by sudo. If omitted uses user which runs the script (no sudo)
  -c USER_COMMAND       command and it's options that should be executed, needs to be ONE string
  -f CONFIG, --config CONFIG
                        location of config file (Default: /etc/hooked.ini)
```

Full sample config file:

```ini
[hooked]
bind = 127.0.0.1
port = 8080
secret = mysecret
basicauth = user:password
no_auth = true
sudo_user = hooked
user_command = /full/path/to/binary with subcommands and options -v

[webhook]
# If url in webhook section is defined, hooked will send a post request to this url
url = https://example.com/

# JSON payload for success, if omitted json body will be an empty string
# only specify either 'payload_success' or 'payload_success_file'
# 'payload_success' expects a json string
# 'payload_success_file' expects a file path
payload_success_file = /path/to/payload_success.json

# JSON payload for error, if omitted json body will be an empty string
# only specify either 'payload_error' or 'payload_error_file'
# 'payload_error' expects a json string
# 'payload_error_file' expects a file path
payload_error_file = path/to/payload_error.json
```
