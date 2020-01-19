import os
import sys
import socket
import threading
import ssl
import time
import select
import errno
from datetime import datetime
from builtins import Exception
from time import mktime
from datetime import timedelta
from subprocess import Popen, PIPE
import base64
import hashlib
import signal
from random import random
import queue


class Sender(threading.Thread):
    def __init__(self, proto, logger, sh_instance, message_queues):
        threading.Thread.__init__(self)
        self.sh = sh_instance
        self.logger = logger
        self._proto = proto
        self.socks_write = []
        self.message_queues = message_queues
        self.debug_level = 99
        self.client = None
        self.server = None
    
    def run(self):
        self.alive = True
        while self.alive:
            readable, writable, excpetional = select.select([], self.socks_write, self.socks_write)
            for myActSock in writable:
                #==============================
                try:
                    next_msg = b''
                    next_msg = self.message_queues[myActSock].get_nowait()
                except queue.Empty:
                    #pass
                    continue
                    
                else:
                    if (self.debug_level > 5):
                        try:
                            self._proto.addEntry('INFO    ', 'sending "%s" to %s' % (next_msg, myActSock.getpeername()))
                            self._proto.addEntry('INFO (S)','Queue-Length-CLIENT : {} / Queue-Length-SERVER : {}'.format(self.message_queues[self.client].qsize(),self.message_queues[self.server].qsize()))
                        except:
                            pass
                    if self.debug_level > 5:
                        try:
                            if myActSock == self.server:
                                myRcv = 'P>S' 
                            else:
                                myRcv = 'P>C'
                            self._proto.addEntry('INFO (S)',self.name+"Block-length : {}".format(len(next_msg)))
                            self._proto.addEntry('INFO '+myRcv,self.name+'sending DATA to {}'.format(myActSock.getpeername()[0]))
                            self.logger.debug('sending DATA to {}'.format(myActSock.getpeername()[0]))
                        except:
                            pass
                    #self._proto.addEntry('INFO (S)',self.name+'Start - Send-Message to : {}'.format(myActSock.getpeername()[0]))
                    time1 = datetime.now()
                    blocklength = len(next_msg)
                    while len(next_msg) > 0:
                        sent = myActSock.send(next_msg)
                        if sent < len(next_msg):
                            next_msg = next_msg[sent:]
                        else:
                            break
                    if self.debug_level > 5:
                        time2 = datetime.now()
                        sendtime = time2-time1
                        self._proto.addEntry('INFO (S)',self.name+' - send-duration {} - Send-Message to : {} - block-length : {}'.format(sendtime, myActSock.getpeername()[0],blocklength))
                        #self._proto.addEntry('INFO (S)',self.name+'Stop - Send-Message to : {}'.format(myActSock.getpeername()[0]))
                
            
        
    def stop(self):
        self._proto.addEntry('INFO (S)',self.name+' Stopped')
        try:
            self.socks_write.remove(self.client)
        except:
            pass
        try:
            self.socks_write.remove(self.server)
        except:
            pass
        self.alive = False
        
        
        
