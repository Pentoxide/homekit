#!/usr/bin/env python3
"""
Module retrieve messages from Redis and push them to remote
server via http using HMAC signature
"""

import sys
import ast
import time
import signal
import asyncio
import hmac
import base64
from hashlib import sha1
import configparser
import aioredis
import requests

def process_data_from_redis(message, secret):
    """
    Convert message from Redis into POST data and HMAC signature
    """
    key, value = list(message)
    timestamp, seq_id = key.decode('utf-8').split('-')
    data = {'timestamp': int(timestamp[:-3]), 'id': int(seq_id)}
    for i in value:
        try:
            data[i.decode('utf-8')] = int(value[i].decode('utf-8'))
        except ValueError:
            data[i.decode('utf-8')] = value[i].decode('utf-8')
    data_encoded = str(data).encode('utf-8')
    hashed = hmac.new(secret, data_encoded, sha1)
    signature = base64.b64encode(hashed.digest()).decode('utf-8')
    return (data_encoded, signature)

def signal_handler(signum, frame):
    """
    Handler for Ctrl-C or kill termination
    """
    print("Caught: signum %s, frame %s" % (signum, frame))
    raise BaseException('Interrupted')

async def main():
    """
    Main process function
    """
    connection = await aioredis.create_redis(REDIS_SERVER)
    stream_length = await connection.xlen(REDIS_STREAM)
    if stream_length > 0:
        print("Gathering %s message(s)" % stream_length)
        result = await connection.xrange(REDIS_STREAM, start="-", stop="+")
        for i in result:
            secret = SHARED_SECRET[int((time.time() + SHARED_OFFSET)
                                       / SHARED_DEVIDER) % SHARED_MODULO]
            data, signature = process_data_from_redis(i, secret)
            headers = {"X-Signature": signature}
            try:
                response = requests.post(REMOTE_SERVER, data=data, headers=headers)
                if response.status_code == 200:
                    await connection.xdel(REDIS_STREAM, list(i)[0].decode('utf-8'))
                    print("Data transfered and deleted from Redis")
                else:
                    print(response.status_code, response.text)
            except Exception as error:
                print(error, "Something went wrong")
            except BaseException:
                print("Closing connection...")
                connection.close()
                await connection.wait_closed()
                print("Connection closed, exiting...")
                sys.exit(0)
        connection.close()
        await connection.wait_closed()

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    CONFIG = configparser.ConfigParser()
    CONFIG.read(sys.argv[1])
    REMOTE_SERVER = CONFIG.get("general", "remote_server")
    REDIS_SERVER = CONFIG.get("general", "redis_server")
    REDIS_STREAM = CONFIG.get("general", "redis_stream")
    SHARED_SECRET = ast.literal_eval(CONFIG.get("crypto", "shared_secret"))
    SHARED_OFFSET = int(CONFIG.get("crypto", "shared_offset"))
    SHARED_DEVIDER = int(CONFIG.get("crypto", "shared_devider"))
    SHARED_MODULO = int(CONFIG.get("crypto", "shared_modulo"))
    asyncio.run(main())
