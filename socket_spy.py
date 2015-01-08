#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# 示意图
#
# Client               Socket-Spy               Server
#  ---                  --------                 ---
# |   |    c_socket    |        |   s_socket    |   |
# | C | <--------------+--RECV--+-------------- | S |
# |   | ---------------+--SEND--+-------------> |   |
# |   |                |        |               |   |
#  ---                  --------                 ---
#


from SocketServer import *
import socket
import time
import select
import threading
import sys
import os
import fcntl


VERSION = "1.2.0"


import optparse
loOptParser = optparse.OptionParser(usage="socket_spy [options]", version="socket_spy-%s" % VERSION)
loOptParser.add_option("-s", action="store", dest="listen_host", type="string", help="Local host name to listen on")
loOptParser.add_option("-p", action="store", dest="listen_port", type="int", help="Local TCP port number to listen on")
loOptParser.add_option("-S", action="store", dest="forward_host", type="string", help="Remote host name to listen on")
loOptParser.add_option("-P", action="store", dest="forward_port", type="int", help="Remote TCP port number to listen on")
loOptParser.add_option("--send_speed", action="store", dest="send_speed", type="int", default=-1, help="the send speed limit, Kb/s")
loOptParser.add_option("--recv_speed", action="store", dest="recv_speed", type="int", default=-1, help="the recv speed limit, Kb/s")
loOptParser.add_option("-c", action="store", dest="capture", type="string", help="Specify a path to save captured packet")
loOptParser.add_option("-V", action="store_true", dest="verbose", help="print verbose debug log")
options, args = loOptParser.parse_args()
verbose_log = open("socket_spy.log", 'w')
verbose_log.write("start logging")
verbose_log.flush()

try:
  options.listen_port = int(options.listen_port)
except:
  options.listen_port = 45679

if type(options.listen_host) != type(""):
  options.listen_host = socket.gethostname()

try:
  options.forward_port = int(options.forward_port)
except:
  options.forward_port = 45679

if type(options.forward_host) != type(""):
  options.forward_host = "localhost"

if options.capture :
  capture_file = os.path.join(options.capture, 'capture.log')
  #filehandle = open(capture_file, 'w')

def od_show(s):
  j = 0
  show = code = ""
  for i in xrange(len(s)):
    show += ('%s' % (repr(s[i]))[1:-1]).center(4)
    code += ' %02X ' % ord(s[i])
    if (i + 1) % 16 == 0:
      print '%04X'%j, show
      print '%04X'%j, code
      print
      show = code = ""
      j += 16

  if code != "":
    print '%04X'%j, show
    print '%04X'%j, code

def capture(all_data, data, found_header_end, http_end, type, url, conn=None):

  new_line = '\r\n'

  print '='*12+'before capture'
  print 'conn:', conn
  print 'url:', url
  print 'type:', type
  print 'if all_data is data:', all_data == data 
  print 'found header end:', found_header_end
  print 'http end:', http_end
  
  #found_header_end == True and http_end == True
  #上次请求已接受完，这次是新的请求
  
  #found_header_end == True and http_end == False
  #上次请求的header部分已收完，但body未收完，这次继续

  #found_header_end == False and http_end == True
  #异常情况
  
  #found_header_end == False and http_end == False
  #上次请求的header部分未收完，这次继续

  debug = False
  #if 'GET http://uctest.ucweb.com:8088/header/accept/control-js.php' in data:
  #if 'GET http://uctest.ucweb.com:8088/header/accept/accept-client.php' in data:
  #  debug = True
  #  print repr(data)

  if http_end :
    all_data = data
    http_end = False
    found_header_end = False
    if type == 'Request':
      url = None

  if not found_header_end :
    if debug:
      print 'not found_header_end'
    http_end_position = all_data.find(new_line*2)
    if http_end_position >= 0:
      if debug:
        print 'http_end_position >= 0'
      found_header_end = True
      http_header = all_data[:http_end_position+2]
      http_body = all_data[http_end_position+2:]
      if not url:
        headers = http_header.split(new_line)
        url = headers[0].split()[1]
      
      filehandle = open(capture_file, 'a')
      fcntl.flock(filehandle, fcntl.LOCK_EX)
      filehandle.write("!---New %s: %s---!%s" % (type, url, new_line) )
      filehandle.write(http_header)
      filehandle.write("!---End %s: %s---!%s" % (type, url, new_line) )
      filehandle.flush()
      fcntl.flock(filehandle, fcntl.LOCK_UN)
      filehandle.close()

  if found_header_end:
    http_end = is_http_end(all_data, new_line)

  print '-'*12+'after capture'
  print 'url:', url
  print 'type:', type
  #all_data == data表示这次处理的是一个新的请求
  print 'if all_data is data:', all_data == data 
  #这次capture时是否已发现了数据中的header结束位置
  print 'found header end:', found_header_end
  #这次capture时是否已发现了数据中的整个http请求/应答的结束位置，是的话表示这次处理的请求已结束
  print 'http end:', http_end
  print '='*12+'capture done'

  return all_data, data, found_header_end, http_end, url

def is_http_end(http, new_line):

  if http.find(new_line*2) <0 :
    return False

  headers, body = http.split(new_line*2, 1)
  #if 'GET http://uctest.ucweb.com:8088/header/accept/accept-client.php' in http:
  #  print repr(headers), repr(body)
  headers = headers.split(new_line)

  if headers[0].startswith('GET'):
    return True

  for head in headers:
    if head == headers[0] or len(head) == 0:
      continue
    key, value = head.split(':', 1)

    if key.strip().lower() == 'transfer-encoding' and value.strip().lower() == 'chunked':
      if body.endswith('0'+new_line*2):
        return True

    elif key.strip().lower() == 'content-length':
      content_length = int(value)
      if len(body) >= content_length :
        return True

  return False
      
class clsServerThread(threading.Thread):
  def __init__(self, handler):
    threading.Thread.__init__(self)
    self.handler = handler
    if options.verbose:
        print 'clsServerThread(threading.Thread) start'

  def run(self):
    s_data = ""
    found_header_end = True
    is_chunked = False
    http_end = True
    try:
      while 1:
        if self.handler.socket_close:
          print " ^^^ server socket close by notice from client, ConnSeq=%i" % self.handler.ConnSeq 
          break
        (readable, writeable, exceptable) = select.select([self.handler.s_socket], [], [self.handler.s_socket], 1.0)
        if not (readable == exceptable == []):
          data = self.handler.s_socket.recv(2048)
          if not data: 
            raise socket.error
          else:
            s_data += data
            if 0 < options.recv_speed:
              print " ^^^ s_socket recv %s on %s" % (len(data), time.time())
              sleep_time = float(float(len(data))/(1000*options.recv_speed))
              time.sleep(sleep_time)
            if options.verbose:
              verbose_log.write('\n\nServer %i: ====================================================\n' % self.handler.ConnSeq)
              verbose_log.write(data)
              verbose_log.flush()
              #od_show( data )
            if options.capture:
              s_data, data, found_header_end, http_end, url = capture(s_data, data, found_header_end, http_end, "Response", self.handler.url)

            self.handler.c_socket.send(data)
            if options.verbose:
                print 'c_socket http_end: ',http_end, ', c_socket:', self.handler.c_socket, ', s_socket:', self.handler.s_socket
    except Exception, e:
      print " ^^^ server exception, ConnSeq=%i\n%s" % (self.handler.ConnSeq, e)
      self.handler.socket_close = True

    print " ^^^ server socket close, ConnSeq=%i" % self.handler.ConnSeq
    self.handler.s_socket.close()
    print " ^^^ server recv data %s" % (len(s_data))


class clsProxyHandler(StreamRequestHandler):

  def setup(self):
    StreamRequestHandler.setup(self)
    self.url = ''

  def handle(self):
    print 'new handler', self
    import re
    host_match = re.compile('Host:\W*%s:%s'%(options.listen_host, options.listen_port))
    host_replace = 'Host: %s:%s'%(options.forward_host, options.forward_port)
    global giConnSeq
    giConnSeq = giConnSeq + 1
    self.ConnSeq = giConnSeq

    print "\n *** New connected by %s, ConnSeq=%i" % (self.client_address, self.ConnSeq)

    # try to connect to the server 
    # if connect sucess, then start a thread to check this socket(s_socket)

    self.c_socket = self.connection
    if 0 < options.send_speed:
      self.c_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2)
    if 0 < options.recv_speed:
      self.c_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2)

    try:
      self.s_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.s_socket.connect((options.forward_host, options.forward_port))
      self.socket_close = False
      print " *** connect to server success, ConnSeq=%i" % self.ConnSeq
      if 0 < options.send_speed:
        self.s_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2)
      if 0 < options.recv_speed:
        self.s_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2)

      # start the a new thread
      svr_thread = clsServerThread(self)
      svr_thread.start()

      # the original thread to check the client (c_socket)

      c_data = ""
      found_header_end = True
      is_chunked = False
      http_end = True

      try:
        while 1:
          if self.socket_close:
            print " ^^^ client socket close by notice from server, ConnSeq=%i" % self.ConnSeq 
            break
          (readable, writeable, exceptable) = select.select([self.c_socket], [], [self.c_socket], 1.0)
          if not (readable == exceptable == []):
            data = self.c_socket.recv(2048)
            if not data: 
              raise socket.error
            else:
              c_data += data
              if 0 < options.send_speed:
                print " ^^^ c_socket recv %s on %s" % (len(data), time.time())
                sleep_time = float(float(len(data))/(1000*options.send_speed))
                time.sleep(sleep_time)
              if options.verbose:
                if data[:data.find(' ')] in ('GET', 'POST','PUT'):
                  data = host_match.sub(host_replace, data, 1)
                verbose_log.write('\n\nClient %i(%s): ++++++++++++++++++++++++++++++++++++++++++++++++++++\n' % (self.ConnSeq, self.client_address))
                verbose_log.write(data)
                verbose_log.flush()
              if options.capture:
                c_data, data, found_header_end, http_end, self.url = capture(c_data, data, found_header_end, http_end, "Request", self.url, self.ConnSeq)
              self.s_socket.send(data)
              if options.verbose:
                  print 's_socket http_end: ',http_end, ', c_socket:', self.c_socket, ', s_socket:', self.s_socket
          else:
            pass
      except Exception, e:
        print " ^^^ client exception, ConnSeq=%i\n%s" % (self.ConnSeq, e)
        self.socket_close = True

      #self.s_socket.send(c_data)
      print " ^^^ client recv data %s" % (len(c_data))

      svr_thread.join()

    except Exception, e:
      print " ^^^ connect to server fail, ConnSeq=%i\n%s" % (self.ConnSeq, e)

    print " ^^^ client socket close, ConnSeq=%i" % self.ConnSeq 
    self.c_socket.close()


class SocketSpyServer(ThreadingTCPServer):
  allow_reuse_address = True


giConnSeq = 0
gsIP = socket.gethostbyname(options.listen_host)
print "Listening on: %s(%s):%i ...\r\n"%(options.listen_host, gsIP, options.listen_port)
print "Proxy to: %s:%i ...\r\n"%(options.forward_host, options.forward_port)
lo_svr = SocketSpyServer((options.listen_host, options.listen_port), clsProxyHandler)
#lo_svr.handle_request()
lo_svr.serve_forever()

# EOF
