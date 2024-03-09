#!/usr/bin/python
import os, sys, socket, stat
from socket import socket,inet_aton,AF_INET,SOCK_STREAM,SOL_SOCKET,SO_REUSEADDR,SO_REUSEPORT
from struct import pack,unpack

DEBUG = 0
OP_STAT = 1
OP_LS = 2

def dbgprint(s):
  if DEBUG:
    print(s)

def sendpkt(sock, data):
  if type(data) == str:
    data = data.encode("utf-8")
  sock.send(pack("I",len(data)) + data)

def recvpkt(sock):
  try:
    pktsize = sock.recv(4)
    if pktsize:
      pktsize = unpack("I",pktsize)[0]
      pkt = sock.recv(pktsize)
      return pkt
  except:
    return None

srvsock = socket(AF_INET, SOCK_STREAM)
srvsock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
srvsock.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)

listen_addr = inet_aton("0.0.0.0")
listen_port = 31338

srvsock.bind(("0.0.0.0", listen_port))
srvsock.listen()

while True:
  (peersock, peerinfo) = srvsock.accept()
  if peersock:
    dbgprint("New client {}:{}".format(peerinfo[0],peerinfo[1]))
    while True:
      pkt = recvpkt(peersock)
      if not pkt:
        break
      (op, plsize) = unpack("II", pkt[0:8])
      pl = unpack("{}s".format(plsize),pkt[8:])[0]

      if op == OP_STAT or op == OP_LS: #stat the fs object first
        objpath = pl.decode("utf-8", errors='ignore')
        dbgprint("Checking {}".format(objpath))

        FORMAT_SUCCESS = '{{"result":"success","path":"{}","size":"{}","mtime":"{}","atime":"{}","ctime":"{}","uid":"{}","gid":"{}","mode":"{}"}}'
        FORMAT_NOTPERMITTED = '{{"result":"failure","error":"operation not permitted","path":"{}"}}'
        FORMAT_LSNOTALLOWED = '{{"result":"failure","error":"listing not allowed","path":"{}"}}'
        FORMAT_NOTFOUND = '{{"result":"failure","error":"file not found","path":"{}"}}'

        try:
          objstat = os.stat(objpath, follow_symlinks=False)
          resp_data = FORMAT_SUCCESS.format(
                                  objpath,
                                  objstat.st_size, 
                                  objstat.st_mtime,
                                  objstat.st_atime,
                                  objstat.st_ctime,
                                  objstat.st_uid,
                                  objstat.st_gid,
                                  objstat.st_mode
                                  )

          if op == OP_LS and stat.S_ISDIR(objstat.st_mode) : #list the directory in case of OP_LS
            dbgprint("Listing directory {}".format(objpath))
            try:
              root, dirs, files = next(os.walk(objpath))
              items = dirs + files
              for item in items:
                dbgprint(" Listing new item {}".format(root+"/"+item))
                objstat = os.stat(root+"/"+item, follow_symlinks=False)
                try:
                  resp_data += "\n" + FORMAT_SUCCESS.format(
                                        root+"/"+item,
                                        objstat.st_size, 
                                        objstat.st_mtime,
                                        objstat.st_atime,
                                        objstat.st_ctime,
                                        objstat.st_uid,
                                        objstat.st_gid,
                                        objstat.st_mode
                                        )
                except FileNotFoundError:
                  resp_data += "\n" + FORMAT_NOTFOUND.format(objpath)
                except PermissionError:
                  resp_data += "\n" + FORMAT_NOTPERMITTED.format(objpath)
            except StopIteration:
              resp_data += "\n" + FORMAT_LSNOTALLOWED.format(objpath)
        except FileNotFoundError:
          resp_data = FORMAT_NOTFOUND.format(objpath)
        except PermissionError:
          resp_data = FORMAT_NOTPERMITTED.format(objpath)
        sendpkt(peersock, resp_data) #finally send collected response data
      continue
    peersock.close()
  continue

peersock.close()
