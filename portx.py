#!/usr/bin/env python
# A small port yoctoarchitecture!
# This program is optimized for Python 2.7.12, Python 3.7.x and Python 3.9.x
# It may run on any other version with/without modifications.
## For best compatibility ###
from __future__ import (print_function, division,
 absolute_import)
#########################
import array, struct, os
import argparse
import optparse
import urllib.request
import urllib.parse
import random
import socks
import io
import socket
import sys
import time
import requests
import asyncio
import re
import dns.zone
import dns.resolver
import errno
import logging
# Use of this source code is governed by the MIT license.
__license__ = "MIT"


#Use TOR in portx
TOR_SERVER = "127.0.0.1"
TOR_PORT = 9050

#Default server in Portx
SERVER = "127.0.0.1"
PORT = 80


#Connect portx_api
class PortApi():
    portx_api={
        'access_key' : '',
        'secret_key' : '',
        'affiliate_id' : ''
}


captured_data = dict()
ipaddress = input("Enter ip address or domain for port scanning:")
port_init=  input("Enter first port: ")
port_end =  input("Enter last port:  ")
pinf = input("Enter port to sniff:")
speed = input("Enter port speed: ") #experiment

port_speed = []
port_payload = []

max = 1
######################
#####PORTX ARCHi#######
######################


######################
#####PORTX DELAY#####
######################

async def port_delay(delay, time):
    await asyncio.sleep(delay)
    return time


######################
#####PORTX DEBUG######
######################
async def port_debug(portdebug):
#[NOT IN USE]
    pd = sys.get_debug(portdebug)
    pd.getnameinfo()
    return time

######################
#####PORTX ERRORS#####
######################

def port_errors(port):
    try:
        with open(port) as f:
            return f.read()
    except IOError as e:
        if e.errno == errno.ENOENT:
            return port
        else:
            raise
    except FileNotFoundError as e:
        return port
######################
#####PORTX LOGGER#####
######################

def port_logg(*args, **kwargs):
    pl_0 = logging.getLogRecordFactory()
    pl_1 = logging.getLevelName(0<3)
    pl_2 = logging.debug()
    pl_3 = logging.info()
    pl_4 = logging.warning()
    pl_5 = logging.error()
    pl_6 = logging.critical()
    pl_7 = logging.exception()
    pl_8 = logging.log()
    pl_9 = logging.shutdown()
    pl_10 = logging.captureWarnings()

    record = pl_0(*args, **kwargs)
    record.getLogRecordFactory = 0xdecafbad
    return record

class PortAttribError(Exception):
    """ PortAttribError not found. """
    def __init__(self, *args, **kwargs):
        pass





######################
#####PORTX LOOPER#####
######################

def port_loop(self, port=None):
    self.preloop()
    if port is None: port = self.port
    print(port)
    port_flag = False

    while not port_flag:
        try:
            s = input(self.prompt)
        except EOFError: s='EOF'
        else: s = self.precmd(s)
        port_flag = self.onecmd(s)
        port_flag = self.postcmd(port_flag, s)
        self.poostloop()

######################
#####PORTX SPEED######
######################

def port_peed(self):
    for self.speed in range(step=1):
        port_speed[self.speed].byteorder()
        port_speed[self.speed].reload()
    for speed in range(step=2):
        port_speed[self.speed].byteorder()
    for speed in range(step=3):
        port_speed[self.speed].byteorder()
    if len(port_speed) > 3:
        print("Error! only 3 levels")
        sys.close()

######################
#####PORTX mDomain####
######################

def mdomain(domain):
    answer = dns.resolver.query(domain, 'A')
    for i in range(0, len(answer)):
        print("IPV4", answer[i])

        try:
            answer6 = dns.resolver.query(domain, 'AAAA')
            for i in range(0, len(answer6)):
                print("IPV6", answer6[i])
        except dns.resolver.NoAnswer as e:
            print("",e)
            try:
                mx = dns.resolver.query(domain, 'MX')
                print("" % mx.response.to_text())
                for data in mx:
                    print("", data.exchange.to_text(), '', data.preference)
            except dns.resolver.NoAnswer as e:

                print("",e)
                try:
                    ns_answer = dns.resolver.query(domain, 'NS')
                    print("" %[x.to_text() for x in ns_answer])
                except dns.resolver.NoAnswer as e:

                    print("", e)



######################
#####PORTX SNIFFER####
######################
def port_sniff(data):
    if not data:
        return

    portstack = port_stack.parse(data)
    payload = portstack.socket.getservbyport()

    print(payload)


######################
#####PORTX INJECTION##
######################
def port_injection(pinj):
    pinj = socket.socket(socket.AF_INET6, socket.SOCK_SEQPACKET)

    i = 999999;
    for pinj in list(range(i>0)):
        print("Sort", pinj)
    for pinj in socket.error:
        print("error in port", pinj)

class portNoAppend(list):
 def __getattribute__(self, data):
     if data == 'port append':
         raise AttributeError(data)
     return list.__getattribute__(self, data)

class removeNoPorts(list):
    def __getattribute__(self, port):
        if port == 'Removed ports from list':
            raise AttributeError(port)
        return list.__delattr__(self, port)

class airPortCompression():
    def __getattribute__(self, item):
        ra

######################
#####PORTX BINDER#######
######################
def port_binder(proto):


    # create a raw socket and bind it to the public interface
    if os.name == "nt":
        socket_protocol = socket.IPPROTO_IP
    elif os.name == "nt":
        socket_protocol = socket.BTPROTO_RFCOMM
    elif os.name == "nt":
        socket_protocol = socket.IP_MULTICAST_IF
    elif os.name == "nt":
        socket_protocol = socket.IP_DEFAULT_MULTICAST_TTL
    else:
        socket_protocol = socket.IPPROTO_ICMP

        # read in a single packet

        try:
            print (socket_protocol)
        except socket.error as error_msg:
            sys.exc_info()
        try:
            print(captured_data.recvfrom(65565))
        except socket.error as error_msg:
            sys.exit()


######################
#####PORTX SHELL##
######################
async def sell_env():
    shell = os.environ.get('COMSPEC')
    if shell is None: shell = os.environ.get('SHELL')
    if shell is None: shell = 'an unknown command processor'
    print("Running", shell)


######################
#####PORTX MONITORING#
######################
def monitor_packet(pkt):
    if IP in pkt:
        if pkt[IP].src not in captured_data:
            captured_data[pkt[IP].src] = []

    if TCP in pkt:
        if pkt[TCP].sport <= port_end:
            if not str(pkt[TCP].sport) in captured_data[pkt[IP].src]:
                captured_data[pkt[IP].src].append(str(pkt[TCP].sport))

    os.system('clear')
    ip_list = sorted(captured_data.keys())
    for key in ip_list:
        ports = ', '.join(captured_data[key])
        if len(captured_data[key]) == 0:
            print('%s' % key)
        else:
            print('%s (%s)' % (key, ports))


######################
#####PORTX IP#########
######################

def get_ip_address(new_sock, address):



    print('Connected from', address)
    while True:
        received = new_sock.recv(1024)
        if not received:
            break
        s = received.decode('utf-8', errors='replace')
        urllib.urlcleanup()
        print('Recv:', s)
    new_sock.sendall(received)
    print('Echo:', s)
    new_sock.close()
    print('Disconnected from', address)


servsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
servsock.bind((TOR_SERVER, TOR_PORT)) #Customize
servsock.listen(5)
#print('Serving at', servsock.getsockname())

######################
#####PORTX TOR##
######################
def tor_path(path):
    try:
        conn = httplib.HTTPConnection(urllib.request.request_host())
        conn.request('GET', url.path, None)
        data = conn.getresponse().read()
    except:
        print("Cannot connect....")
        return

    if len(data) == 0:
        print("Got 0 bytes.. try again!", path)
        return

#TODO
def find_port_module(self, *args, **kwargs):
    """"find_port_module"""
    return None
#TODO
def create_port_module(self, *args, **kwargs):
    """"create_port_module"""
    return None
#TODO
def inject_port_module(self, *args, **kwargs):
    """"inject_port_module"""
    return None

#TODO
def reload_bad_port_module(self, *args, **kwargs):
    """reload_bad_port_module"""
    return None


#TODO
def port_splitter(self):
    self.split_raw(0)
    self.split_half(2)
    return None

######################
#####PORTX SCANNER####
######################
def scan_ports(host, start_port, end_port):


    for port in range(int(port_init), int(port_end) + 1):
        buffering = io.DEFAULT_BUFFER_SIZE

        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

        sock.settimeout(2)
        result = sock.connect_ex((ipaddress, port))



        if result == 0:
            print(port, "--> Open", time.process_time())

        elif result == 1:
            print(port_load, "Searching..", sock)
            #time.process_time()

        else:
            print(port, "--> Closed", " Time:", time.process_time(),"Buffer size -->", buffering)


            sock.close()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as err_msg:
        print('Socket creation failed. Error code: ' + str(err_msg[0]) + ' Error mesage: ' + err_msg[1])
        sys.exit()

    try:

        slays = time.process_time()

        print("Wait for the scanner to finnish", slays)

    except socket.error:
        pass
    #Catch IP of remote_ip
    try:
        remote_ip = socket.gethostbyname(host)
    except socket.error as error_msg:
        print(error_msg)
        sys.exit()

    #Scanning
    end_port += 1

    for port in range(start_port, end_port):



        try:
            sock.connect((remote_ip, port))

            print('Port ' + str(port) + ' is Open')
            sock.close()


            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            pass  # skip errors


######################
#####PORTX __INIT__###
######################

def __init__(self, port_load):
    if port_load != self.port_payload:
        raise ImportError
######################
#####PORTX MAIN#######
######################

if __name__ == '__main__':

    try:
        import sys
        pass
    except PendingDeprecationWarning:
        import sys
        raise Warning()
    except SystemError:
        import sys
        raise Warning()
    except KeyboardInterrupt:
        import sys
        raise SystemExit()
    except EnvironmentError:
        import sys
        raise SystemExit()
    except ValueError:
        import sys
        raise SystemExit()
    except OverflowError:
        import sys
        raise SystemExit()
    except OSError:
        print('Error sending CAN frame')
    except BrokenPipeError:
        pass
    finally:
        servsock.close()

    #Commandline

    parser = argparse.ArgumentParser(description='Remote Port Scanner')
    parser.add_argument('--host', action="store", dest="host", default='localhost')#required=True
    parser.add_argument('--monitoring', action="store", dest="monitor_packet", default=0, type=int)
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    #parser.parse_args(['--version'])
    parser.add_argument('--address', action="store")
    parser.add_argument('--start-port', action="store", dest="start_port", default=1, type=int)
    #parser.parse_args(['--start-port'])
    parser.add_argument('--end-port', action="store", dest="end_port", default=100, type=int)
    given_args = parser.parse_args()
    host, start_port, end_port, monitor_packet =  given_args.host, given_args.start_port, given_args.end_port, given_args.monitor_packet
    scan_ports(host, start_port, end_port)
    monitor_packet(pkt)
    port_binder(proto)





