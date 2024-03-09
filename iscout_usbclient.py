#!/usr/bin/env python3

import functools, argparse
import ctypes, struct, plistlib
import io, sys, time, select
from datetime import datetime
from socket import socket,inet_aton
from struct import pack,unpack
from json import loads

RECV_TIMEOUT=10*60 #timeout in seconds to drop capture if no traffic arrives
DEBUG=1

OP_STAT = 1
OP_LS = 2

OP_TO_ID = { "stat":OP_STAT, "ls":OP_LS }

def dbgprint(s):
  if DEBUG:
    sys.stdout.buffer.write("{}\n".format(s).encode("utf-8"))

def ts2date(ts):
 #convert strings with floats to datetime
  return datetime.fromtimestamp(int(float(ts)))

def load_cdll():
  if sys.platform == 'linux':
    for n in (6, 5, 4, 3, 2, 1, 0):
      for sfx in ('-1.0', ''):
        try:
          return ctypes.CDLL('libimobiledevice{}.so.{}'.format(sfx, n))
        except OSError:
          pass
    raise OSError('libimobiledevice not found!')
  elif sys.platform == 'win32':
    import hashlib, tempfile, shutil, os
    from zipfile import ZipFile
    from urllib.request import urlopen
    if sys.maxsize >> 32:
      imd_url = 'https://github.com/libimobiledevice-win32/imobiledevice-net/releases/download/v1.3.17/libimobiledevice.1.2.1-r1122-win-x64.zip'
    else:
      imd_url = 'https://github.com/libimobiledevice-win32/imobiledevice-net/releases/download/v1.3.17/libimobiledevice.1.2.1-r1122-win-x86.zip'
    imd_comp = 'imobiledevice-' + hashlib.sha1(imd_url.encode()).hexdigest()
    imd_dir = os.path.join(tempfile.gettempdir(), imd_comp)
    dll_path = os.path.join(imd_dir, 'imobiledevice.dll')
    if not os.path.exists(dll_path):
      print('Downloading libimobiledevice ...', file=sys.stderr)
      dnld_dir = imd_dir + '-download'
      dnld_zip = dnld_dir + '.zip'
      with urlopen(imd_url) as in_fd, open(dnld_zip, 'wb') as out_fd:
        shutil.copyfileobj(in_fd, out_fd)
      print('Extracting libimobiledevice ...', file=sys.stderr)
      shutil.rmtree(dnld_dir, ignore_errors=True)
      shutil.rmtree(imd_dir, ignore_errors=True)
      with ZipFile(dnld_zip) as zf:
        zf.extractall(dnld_dir)
      os.rename(dnld_dir, imd_dir)
    ctypes.windll.kernel32.SetDllDirectoryW(ctypes.c_wchar_p(imd_dir))
    return ctypes.CDLL(dll_path)
  else:
    raise OSError('unsupported platform: {}'.format(sys.platform))

cdll = load_cdll()


class LIDError(Exception):
  @classmethod
  def check(cls, err):
    if err != 0:
      raise cls(err)

class IDeviceError(LIDError):
  def __str__(self):
    [code] = self.args
    err = 'Error in libimobiledevice: ' + {
      0: 'Success',
      -1: 'Invalid Argument',
      -2: 'Unknown Error',
      -3: 'No Device',
      -4: 'Not Enough Data',
      -5: 'Bad Header',
      -6: 'SSL Error',
      -7: 'Timeout',
    }.get(code) or 'Unknown Error Code {}'.format(code)
    if code == -3:
      if sys.platform == 'linux':
        err += ' (device not connected? usbmuxd not running?)'
      elif sys.platform == 'win32':
        err += ' (device not connected? iTunes not installed?)'
    return err


class LockdownError(LIDError):
  pass

class LIDContainer(object):
  handle = None
  destructor = None
  error_class = None
  def __init__(self, *args, **kwargs):
    self.handle = self._init_handle(*args, **kwargs)
  def __del__(self):
    if self.handle:
      self.error_class.check(self.destructor(self.handle))
  def _init_handle(self, *args, **kwargs):
    raise NotImplementedError

class IDevice(LIDContainer):
  destructor = cdll.idevice_free
  error_class = IDeviceError
  def _init_handle(self, udid=None):
    udid = udid.encode() if udid is not None else ctypes.c_void_p(0)
    handle = ctypes.c_void_p(0)
    IDeviceError.check(cdll.idevice_new(ctypes.byref(handle), udid))
    return handle

class IDeviceConnection(LIDContainer):
  idevice_connection_receive_timeout = cdll.idevice_connection_receive_timeout
  idevice_connection_receive_timeout.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p,
    ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32),
    ctypes.c_uint]

  idevice_connection_send = cdll.idevice_connection_send 
  idevice_connection_send.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p,
    ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)
  ]

  destructor = cdll.idevice_disconnect
  error_class = IDeviceError
  def _init_handle(self, idevice, port):
    self.idevice = idevice
    handle = ctypes.c_void_p(0)
    IDeviceError.check(cdll.idevice_connect(
      idevice.handle, ctypes.c_uint16(port), ctypes.byref(handle)))
    return handle
  def enable_ssl(self):
    IDeviceError.check(cdll.idevice_connection_enable_ssl(self.handle))
  def disable_ssl(self):
    IDeviceError.check(cdll.idevice_connection_disable_ssl(self.handle))

  def send(self, data):
    out_bytes = ctypes.c_uint32(0)
    ret_code = self.idevice_connection_send(self.handle, data, len(data), ctypes.byref(out_bytes))
    if ret_code != 0 and ret_code != -7:
      IDeviceError.check(ret_code)

  def recv(self, num_bytes):
    self.spoll = select.poll()
    self.spoll.register(sys.stdin, select.POLLIN)
    
    out = bytes(num_bytes)
    out_bytes = ctypes.c_uint32(0)

    time_passed = 0
    local_timeout = 200 #in ms
    ret_code = 0
    while time_passed < RECV_TIMEOUT:
      ret_code = self.idevice_connection_receive_timeout(self.handle, out, num_bytes, ctypes.byref(out_bytes), ctypes.c_uint(local_timeout))
      if self.spoll.poll(0):
        if sys.stdin.buffer.read(1) == b'\n':
          self.print_stats()

      if ret_code != 0 and ret_code != -7:
        IDeviceError.check(ret_code)
      if num_bytes == 0:
        time_passed += local_timeout
        continue
      else:
        break
    if time_passed > RECV_TIMEOUT:
      IDeviceError.check(-7)
    return out[:out_bytes.value]

# based on https://opensource.apple.com/source/xnu/xnu-2050.48.11/bsd/net/iptap.h.auto.html
HEADER_STRUCT = struct.Struct('>IBIBHBIII 16s I 17s I I 17s II')
HEADER_SIZE = HEADER_STRUCT.size
UB32 = struct.Struct('>I')
SL32 = struct.Struct('<i')
UM32 = struct.Struct('=I')
UM16 = struct.Struct('=H')

class DeviceComm(object):
  IN_OUT_MAP = {0x01: 'O', 0x10: 'I'}

  def __init__(self, srvport, udid=None):
    idevice = IDevice(udid=udid)
    port = srvport
    self.conn = IDeviceConnection(idevice, port)  # keep reference to keep fd open
    self._netstat = {}

  def sendpkt(self, data):
    conn = self.conn
    conn.send(pack("I",len(data)) + data)

  def recvpkt(self):
    conn = self.conn
    pktsize = conn.recv(4)
    if pktsize:
      pktsize = unpack("I", pktsize)[0]
      return conn.recv(pktsize)
    else:
      return None

class SessionDriver():
  def __init__(self, devcomm, args, out_file):
    self.devcomm = devcomm
    self.out_file = out_file
    self.args = args

  def process_target(self, cmd, tpath):
    devcomm = self.devcomm
    if tpath:
      s = pack("II{}s".format(len(tpath)), OP_TO_ID[cmd], len(tpath), tpath.encode("utf-8"))
      devcomm.sendpkt(s)
      pkt = devcomm.recvpkt()
      if pkt:
        for pkt_line in pkt.decode("utf-8").split("\n"):
          js = loads(pkt_line)
          res = "+" if js["result"]=="success" else "-"
          if res == "-":
            self.out_file.write("{}|{}|{}\n".format(res, js["path"],js["error"]).encode("utf-8"))
          else:
            self.out_file.write("{}|{}|{}|{}|{}|{}|{}|{}|{:o}\n".format(res, js["path"], js["size"], ts2date(js["mtime"]), ts2date(js["atime"]), ts2date(js["ctime"]), js["uid"], js["gid"], int(js["mode"])).encode("utf-8"))



  def run(self):
    devcomm = self.devcomm
    args = self.args

    self.out_file.write("presence|path|size|mtime|atime|ctime|uid|gid|mode\n".encode("utf-8"))
    if args.path:
      self.process_target(args.cmd, args.path)
    elif args.pathfile:
      with open(args.pathfile,"r") as f:
        while True:
          tpath = f.readline().rstrip("\n")
          if tpath:
            self.process_target(args.cmd, tpath)      
          else:
            break

stderr_print = functools.partial(print, file=sys.stderr)

def main():
  # turn off buffered output
  if isinstance(sys.stdout.buffer, io.BufferedWriter):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer.detach())
  # parse arguments
  class HelpFormatter(argparse.ArgumentDefaultsHelpFormatter):
    def __init__(self, *args, **kwargs):
      kwargs.setdefault('max_help_position', 36)
      super().__init__(*args, **kwargs)
  parser = argparse.ArgumentParser(description='Get fs metainfo from iOS devices.',formatter_class=HelpFormatter)
  parser.add_argument('--udid', help='device UDID (if more than 1 device)')
  parser.add_argument('--cmd', help='Command for the target iscout_server (stat|ls)', required=False, default="stat")

  patharg = parser.add_mutually_exclusive_group(required=True)
  patharg.add_argument('--pathfile', help='list of filepaths', default=None)
  patharg.add_argument('--path', help='Path to check', default=None)

  parser.add_argument('--port', help='port of the iscout server (default: 31338)', required=False, default="31338")
  parser.add_argument('--output', help='output file (print to stdout if not set)', required=False, default="-")
  args = parser.parse_args()

  # open output file
  if args.output==None or args.output == '-':
    out_file = sys.stdout.buffer
    while isinstance(out_file, io.BufferedWriter):
      out_file = out_file.detach()
  else:
    out_file = open(args.output, 'wb', 0)
  
  dbgprint('Printing to {}...'.format('<stdout>' if args.output == '-' else args.output))
  try:
    device_comm = DeviceComm(int(args.port), udid=args.udid)
    session_driver = SessionDriver(device_comm, args, out_file)
    session_driver.run()
    dbgprint('Task finished.')
  except KeyboardInterrupt:
    stderr_print()
    dbgprint('interrupting process...')
    out_file.close()
  except:
    stderr_print()
    raise


if __name__ == '__main__':
  main()
