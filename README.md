# hooked

A simple, general purpose webhook service which executes local commands.

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
                        user that should be used by sudo
  -c USER_COMMAND       command and it's options that should be executed, needs to be ONE string
```
