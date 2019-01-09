#!/usr/bin/python3
from flup.server.fcgi import WSGIServer
from portal_server import app

if __name__ == '__main__':
    WSGIServer(app, bindAddress='/run/webr/python-webr-api.soc').run()
