#!/usr/bin/python
import sys, argparse
from socket import socket,inet_aton
from struct import pack,unpack
from json import loads
from datetime import datetime

DEBUG=1
OP_STAT = 1
OP_LS = 2

OP_TO_ID = { "stat":OP_STAT, "ls":OP_LS }

def dbgprint(s):
  if DEBUG:
    print(s)

def ts2date(ts):
 #convert strings with floats to datetime
  return datetime.fromtimestamp(int(float(ts)))

def sendpkt(sock, data):
  sock.send(pack("I",len(data)) + data)

def recvpkt(sock):
  pktsize = sock.recv(4)
  if pktsize:
    pktsize = unpack("I", pktsize)[0]
    return sock.recv(pktsize)
  else:
    return None

class HelpFormatter(argparse.ArgumentDefaultsHelpFormatter):
  def __init__(self, *args, **kwargs):
    kwargs.setdefault('max_help_position', 36)
    super().__init__(*args, **kwargs)
parser = argparse.ArgumentParser(description='Get fs metainfo from iOS devices.',formatter_class=HelpFormatter)
parser.add_argument('--port', help='port of the iscout server (default: 31338)', required=False, default="31338")

patharg = parser.add_mutually_exclusive_group(required=True)
patharg.add_argument('--pathfile', help='list of filepaths', default=None)
patharg.add_argument('--path', help='Path to check', default=None)

parser.add_argument('--cmd', help='Command for the target iscout_server (stat|ls)', required=False, default="stat")
parser.add_argument('serverhost', help='IP of the target iscout_server')
args = parser.parse_args()

srv_host = args.serverhost
srv_port = int(args.port)

peersock = socket()

try:
  peersock.connect((srv_host, srv_port))
except ConnectionRefusedError:
  print("Failed to connect to {}".format(args.serverhost))
  exit(1)

def process_target(cmd, tpath):
  if tpath:
    s = pack("II{}s".format(len(tpath)), OP_TO_ID[cmd], len(tpath), tpath.encode("utf-8"))
    sendpkt(peersock, s)
    pkt = recvpkt(peersock)
    if pkt:
      for pkt_line in pkt.decode("utf-8").split("\n"):
        js = loads(pkt_line)
        res = "+" if js["result"]=="success" else "-"
        if res == "-":
          print("{}|{}|{}".format(res, js["path"],js["error"]))
        else:
          print("{}|{}|{}|{}|{}|{}|{}|{}|{:o}".format(res, js["path"], js["size"], ts2date(js["mtime"]), ts2date(js["atime"]), ts2date(js["ctime"]), js["uid"], js["gid"], int(js["mode"]) ))


print("presence|path|size|mtime|atime|ctime|uid|gid|mode")
if args.path:
  process_target(args.cmd, args.path)
elif args.pathfile:
  with open(args.pathfile,"r") as f:
    while True:
      tpath = f.readline().rstrip("\n")
      if tpath:
        process_target(args.cmd, tpath)      
      else:
        break

peersock.close()
