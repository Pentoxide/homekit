#!/usr/bin/env python
# coding: utf8

#import os
import sys
import ast
import hmac
import time
import signal
import base64
from hashlib import sha1
from http.server import HTTPServer, BaseHTTPRequestHandler
import configparser
import rrdtool

class SimpleServer(BaseHTTPRequestHandler):
    def _set_headers(self, response_code):
        self.send_response(response_code)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def _html(self, message, response_code):
        """This just generates an HTML document that includes `message`
        in the body. Override, or re-write this do do more interesting stuff.
        """
        self.send_response(response_code)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        content = "<html><body>{message}</body></html>".format(message=message)
        return content.encode("utf8")  # NOTE: must return a bytes object!

    def do_GET(self):
        self.wfile.write(self._html("ok", 200))

    def do_HEAD(self):
        self.wfile.write(self._html("ok", 405))

    def do_POST(self):
        request_headers = self.headers
        content_length = int(request_headers['Content-Length'])
        if "X-Signature" in request_headers:
            signature = request_headers["X-Signature"]
        else:
            signature = ""
        post_data_raw = self.rfile.read(content_length)
        post_data = ast.literal_eval(post_data_raw)
        try:
            if check_message_signature(post_data_raw, signature):
                if get_sensor(post_data["sensor_id"]):
                    if process_message(post_data):
                        self.wfile.write(self._html("ok", 200))
                    else:
                        print("Internal error")
                        self.wfile.write(self._html("error", 500))
                else:
                    print("Unknown sensor ID")
                    self.wfile.write(self._html("error", 403))
            else:
                print("Signature failure", post_data, signature)
                self.wfile.write(self._html("error", 401))
        except ValueError as e:
            print("ValueError: %s" % e)
            self.wfile.write(self._html(e, 500))
        except Exception as e:
            print(e)
            self.wfile.write(self._html(e, 500))

def check_message_signature(data, signature):
    timestamp = time.time()
    secret = SHARED_SECRET[int((timestamp + SHARED_OFFSET)
                              / SHARED_DEVIDER) % SHARED_MODULO]
    secret_previous = SHARED_SECRET[int((timestamp + SHARED_OFFSET - 5)
                                       / SHARED_DEVIDER) % SHARED_MODULO]
    hashed = hmac.new(secret, data, sha1)
    hashed_previous = hmac.new(secret_previous, data, sha1)
    return bool(base64.b64encode(hashed.digest()).decode('utf-8') == signature or
                base64.b64encode(hashed_previous.digest()).decode('utf-8') == signature)

def get_sensor(sensor_id):
    return CONFIG.get("sensors", sensor_id)

def process_message(data):
    rrd_path = "/opt/homekit/rrd"
    filename = "{path}/{sensor}.rrd".format(path=rrd_path, sensor=get_sensor(data["sensor_id"]))
    timestamp = data["timestamp"]
    del data["sensor_id"]
    del data["timestamp"]
    del data["id"]
    return update_rrd(filename, timestamp, data)

def update_rrd(filename, timestamp, data):
    template = ""
    datapoint = "{timestamp}".format(timestamp=timestamp)
    for item in data:
        template += "{item}:".format(item=item)
        datapoint += ":{value}".format(value=data[item])
    template = template.strip(":")
    try:
        rrdtool.update(filename, "-t", template, datapoint)
        return True
    except rrdtool.error as e:
        print("Can't update rrd: %s" % e)
        return False

def signal_handler(signum, frame):
    print("Exited with: signum %s, frame %s" % (signum, frame))
    sys.exit(0)

def run(server_class=HTTPServer, handler_class=SimpleServer, addr="localhost", port=6000):
    server_address = (addr, port)
    httpd = server_class(server_address, handler_class)
    print("Starting httpd server on %s:%s" % (addr, port))
    httpd.serve_forever()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    CONFIG = configparser.ConfigParser()
    CONFIG.read(sys.argv[1])
    SHARED_SECRET = ast.literal_eval(CONFIG.get("default", "shared_secret"))
    SHARED_OFFSET = int(CONFIG.get("default", "shared_offset"))
    SHARED_DEVIDER = int(CONFIG.get("default", "shared_devider"))
    SHARED_MODULO = int(CONFIG.get("default", "shared_modulo"))
    run()
