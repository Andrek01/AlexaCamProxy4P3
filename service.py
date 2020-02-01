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


from .proxy_handler import Sender






class ThreadedServer(threading.Thread):
    def __init__(self,Proto, logger,port, video_buffer,cert_path,cert_path_key, Cams, ClientThreads,proxyUrl,path_user_file,proxy_credentials,proxy_auth_type,onyl_allow_own_IP,sh_instance):
        threading.Thread.__init__(self)
        self.sh = sh_instance
        self.logger = logger
        self.port = int(port)
        self.video_buffer = int(video_buffer)
        self.cert_path = cert_path
        self.cert_path_key = cert_path_key
        self.ClientThreads = ClientThreads
        self.sock = None
        self.FirstRound = True
        self.Cams = Cams
        self.setName('CamProxy4AlexaP3')
        self.cert_dict = ssl._ssl._test_decode_cert(self.cert_path)    
        self.cert_ciphers = 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:'  
        self.cert_ciphers += 'AES256+EDH:ECDHE-RSA-AES256-GCM-SHA384:'
        self.cert_ciphers += 'ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:'
        self.cert_ciphers += 'ECDHE-RSA-AES128-SHA256:DHE-RSA-AES256-GCM-SHA384'
        self.proxyUrl = proxyUrl
        self.myIP = ''
        self.path_user_file = path_user_file
        self.proxy_credentials=proxy_credentials
        self.proxy_auth_type=proxy_auth_type
        self._proto = Proto
        self.onyl_allow_own_IP = onyl_allow_own_IP
        
        
        
            

    def GetMyIP(self, myURL):
        proc = Popen(['ping',myURL,'-c 1'], stdout=PIPE, stderr=PIPE)
        out, err = proc.communicate()
        exitcode = proc.returncode
        myString = out.decode().split("\n")
        myAdress = myString[1]
        myAdress = myAdress.split("(")
        myAdress = myAdress[1].split(")")
        myAdress = myAdress[0].strip()
        return myAdress
    
    def stop(self):
        self.logger.info("ProxyCamAlexaP4: service stopping")
        self.logger.info("ProxyCamAlexaP4: set running to false")
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.logger.info("ThreadedServer - shutdown socket")
        except:
            pass
        try:
            self.sock.close()
            self.logger.info("ThreadedServer - closed socket")
        except:
            pass
        self.alive= False
        
    
        
    def run(self):
        self.alive = True
        self.logger.info("ProxyCamAlexaP4: service starting")
        if self.FirstRound:
                if (self.proxyUrl != ''):
                    self.myIP = self.GetMyIP(self.proxyUrl)
                try:
                    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.sock.bind(('', self.port))
                    self.sock.listen(5)
                    self.FirstRound=False
                    self.alive= True
                    #================================
                    # SSL-Settings
                    #================================

                    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    # add Certificate to context
                    context.load_cert_chain(self.cert_path, self.cert_path_key)  
                    # add ciphers to context
                    context.set_ciphers(self.cert_ciphers)

                except Exception as err:
                    self.logger.error("could not open Socket on Port {} Error : {}".format(self.port,err))
        aktThread = 0        
        while self.alive:
            client, address = self.sock.accept()
            try:

                conn = context.wrap_socket(client, server_side=True)
                '''
                conn = client       # only for Tests
                '''
                # Check if only own IP is allowed
                if (self.onyl_allow_own_IP == True):
                    reqAdress = None
                    self.myIP = self.GetMyIP(self.proxyUrl)
                    reqAdress = address[0]
                    if self.myIP != reqAdress:
                        client.shutdown(socket.SHUT_RDWR)
                        client.close()
                        continue
            except Exception as err:
                self.logger.error("ProxyCam4AlexaP3: SSL-Error - {} peer : {}".format(err,reqAdress))
                self._proto.addEntry('ERROR   ',"SSL-Error - {} peer : {}".format(err,reqAdress))
                client.shutdown(socket.SHUT_RDWR)
                client.close()
                continue

            conn.setblocking(0)
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,1)
 
            try:
                # Clean up old Threads
                for t in self.ClientThreads:
                    if t.alive == False:
                        try:
                            #t.actCam.proxied_bytes +=t.proxied_bytes
                            self.ClientThreads.remove(t)
                        except:
                            self._proto.addEntry('ERROR   ',"While storing proxied Bytes to : {}".format(t.name))
                            pass
                        
                self.ClientThreads.append(ProxySocket(self._proto,conn,address,self.logger,self.Cams,self.video_buffer,self.path_user_file,self.proxy_credentials,self.proxy_auth_type,self.proxyUrl,self.port,self.sh))
                aktThread +=1
                if aktThread > 99999:
                    aktThread = 1
                lastAdded = len(self.ClientThreads )-1
                NewThreadName ="CamThread-{0:06d}".format(aktThread)
                self.ClientThreads[lastAdded].name = NewThreadName
                self.ClientThreads[lastAdded].message_queues[conn] = queue.Queue()


                self.logger.info("ProxyCam4AlexaP3: Added Thread %s" % NewThreadName)
                self._proto.addEntry('INFO    ',"ProxyCam4AlexaP3: Added Thread %s" % NewThreadName)
                #self.ClientThreads[lastAdded].daemon = True
                self.ClientThreads[lastAdded].start()

            except Exception as err:
                self.logger.warning("ProxyCam4AlexaP3: NewThreadError - {}".format(err))
            
            self.logger.debug("ProxyCam4AlexaP3: new Thread added, total Threads:{} ".format(str(len(self.ClientThreads ))))




            
class ProxySocket(threading.Thread):
    def __init__(self,Proto, client, address,logger,cams,videoBuffer=524280, path_User_File = '',proxy_credentials='',proxy_auth_type='NONE',proxy_Url = None,port=0, sh_instance = None):
        threading.Thread.__init__(self)
        self.sh = sh_instance
        self.logger = logger
        self.mysocks = []
        self.client = client
        self.server = None
        self.mysocks.append(client)
        self.message_queues = {}
        self.server_url = False
        self.alive = False
        self.serversend = 0
        self.BUFF_SIZE_SERVER=videoBuffer
        self.cams = cams
        self.proxied_bytes = 0.0
        self.peer = ''
        self.actCam = None
        self.last_Session_Start = datetime.now()
        self.path_User_File = path_User_File
        self.Credentials_Checked = False
        self.Authorization_send = False
        self.proxy_credentials=proxy_credentials
        self.proxy_auth_type=proxy_auth_type
        self.nonce = hashlib.sha1(str(random()).encode()).hexdigest()
        self.user = self.proxy_credentials.split(':')[0] 
        self.pwd = self.proxy_credentials.split(':')[1]
        self.server_auth = False
        self._proto = Proto
        self.proxyUrl = proxy_Url
        self.port = port
        self.client_last_Cseq = 0
        self.server_last_Cseq = 1
        self.authenticate = ""
        self.server_describe = ""
        self.Server_Block_Length = []
        self.BUFF_SIZE_CLIENT=4096
        self.debug_level = 99
        self.handshake = 0
        self.Sender = Sender( self._proto,self.logger,self.sh,self.message_queues)
        
        
        
        
        


        
    def stop(self, txtInfo = ''):
        self.Sender.stop()
        
        self._proto.addEntry('INFO    ',"Server-BlockLength : {}".format(str(self.Server_Block_Length)))
        
        self.logger.debug("{} got STOP signal ".format(self.name))
        self._proto.addEntry('INFO    ',"{} got STOP signal ".format(self.name))
        for s in self.mysocks:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception as err:
                self.logger.debug("Cam Thread cannot shutdown Socket - {}".format(s))
            try:
                s.close()
            except Exception as err:
                self.logger.debug("Cam Thread cannot close Socket - {}".format(s))
        
        try:
            self.mysocks.remove(self.client)
        except:
            pass
        try:
            self.mysocks.remove(self.server)
        except:
            pass
        self.logger.debug("ProxyCam4AlexaP3: Cam Thread stopped - %s" % txtInfo)
        self._proto.addEntry('INFO    ','stopped  Thread {} Reason : {}'.format(self.name, txtInfo))
        self.actCam.proxied_bytes +=self.proxied_bytes
        #self.sh.AlexaCamProxy4P3.cams.Cams[self.actCam.proxied_Url].proxied_bytes += self.proxied_bytes
        try:
            self.actCam.last_Session_End = datetime.now()
            duration_sec = mktime(self.actCam.last_Session_End.timetuple()) - mktime(self.actCam.last_Session_Start.timetuple())
            self.actCam.last_Session_duration = str(timedelta(seconds=duration_sec))
        except:
            self.logger.debug("ProxyCam4AlexaP3: Problem during calculating duration-{}".format(err))
        self.alive = False
        #self.sh.AlexaCamProxy4P3.ClientThreads.remove(self)
        #self.ClientThreads.remove(self)
        
    
    def CreateBasicAuthResponse(self):
        AuthResp = 'RTSP/1.0 401 Unauthorized\r\n'
        AuthResp += 'Server: APC/1.0.0 (Build/489.16; Platform/Linux; Release/Darwin; state/beta; )\r\n'
        AuthResp += 'Cseq: 1\r\n'
        AuthResp += 'WWW-Authenticate: Basic realm="Access2AlexaCam"\r\n\r\n'
       
        return AuthResp
    
    def CreateDigestAuthResponse(self):
        AuthResp = 'RTSP/1.0 401 Unauthorized\r\n'
        AuthResp += 'Server: APC/1.0.0 (Build/489.16; Platform/Linux; Release/Darwin; state/beta; )\r\n'
        AuthResp += 'Cseq: 1\r\n'
        AuthResp += 'WWW-Authenticate: Digest realm="Access2AlexaCam", nonce="'+self.nonce+'"\r\n\r\n'
       
        return AuthResp
    
    def CreateForbiddenResponse(self):
        actDate = datetime.now()
        fmtDate = actDate.strftime('Date: %a, %d %b %H:%M:%S %Z %Y\r\n')
        ForbidResp = 'RTSP/1.0 403 Forbidden\r\n' 
        ForbidResp += fmtDate
        
        return ForbidResp
        
    

        
    def run(self):
        self.Sender.client = self.client
        self.Sender.socks_write.append(self.client)
        self.Sender.name = self.name + "-Sender"
        self.Sender.start()
        
        self.logger.info("ProxyCam4AlexaP3: Cam Thread startet")
        self.alive = True
        serverblock = b''
        clientblock = b''
        loopcount =0
        
        
        
        if 'NONE' in self.proxy_auth_type:
            self.Authorization_send = True
            self.Credentials_Checked = True
            if self.debug_level > 5:
                self._proto.addEntry('INFO    ','Allowed Access without Authorization - NONE')
                self.logger.debug('Allowed Access without Authorization - NONE')
                    
        while self.alive:
            #time.sleep(0.0001)       # give other Threads a Chance
            readable, writable, exceptional = select.select(self.mysocks, [], self.mysocks,3)
            for myActSock in readable:
                
                if myActSock == self.server:
                    try:
                        if self.debug_level > 5:
                            self._proto.addEntry('FLOW-CTL','Reading on Proxy from Camera')
                        self._handleServerBlock(myActSock)
                        
                    except:
                        self._proto.addEntry('ERROR   ','Problem while getting Server-DATA')
                        self.stop("Problem while getting Server-DATA")

                elif myActSock == self.client:
                    try:
                        if self.debug_level > 5:
                            self._proto.addEntry('FLOW-CTL','Reading on Proxy from Client')
                        self._handleClientBlock(myActSock)

                    except:
                        self._proto.addEntry('ERROR   ','Problem while getting Client-DATA')
                        self.stop("Problem while getting Client-DATA")
                    
            '''
            for myActSock in writable:
                #==============================
                try:
                    next_msg = b''
                    next_msg = self.message_queues[myActSock].get_nowait()
                except queue.Empty:
                    pass
                    # No messages waiting so stop checking for writability.
                    #self._proto.addEntry('INFO    ', 'output queue for'+ str(myActSock.getpeername())+ 'is empty')
                    #outputs.remove(s)
                else:
                    #self._proto.addEntry('INFO    ', 'sending "%s" to %s' % (next_msg, myActSock.getpeername()))
                    #s.send(next_msg)
                    if myActSock == self.server:
                        myRcv = 'P>S' 
                    else:
                        myRcv = 'P>C'
                    
                    
                    if (self.server_url and self.debug_level > 5):
                        self._proto.addEntry('INFO    ','Queue-Length-CLIENT : {} / Queue-Length-SERVER : {}'.format(self.message_queues[self.client].qsize(),self.message_queues[self.server].qsize()))
                    if self.debug_level > 5:
                        self._proto.addEntry('INFO    ',"Block-length : {}".format(len(next_msg)))
                        self._proto.addEntry('INFO '+myRcv,'sending DATA to {}'.format(myActSock.getpeername()[0]))
                        self.logger.debug('sending DATA to {}'.format(myActSock.getpeername()[0]))
                    self._proto.addEntry('INFO    ','Start - Send-Message to : {}'.format(myActSock.getpeername()[0]))
                    while len(next_msg) > 0:
                        sent = myActSock.send(next_msg)
                        if sent < len(next_msg):
                            next_msg = next_msg[sent:]
                        else:
                            break
                    self._proto.addEntry('INFO    ','Stop - Send-Message to : {}'.format(myActSock.getpeername()[0]))
                

                #==============================

                if len(self.message_queues[myActSock]) >= 1:
                    try:
                        next_msg = b''
                        #next_msg = self.message_queues[myActSock][0]
                        #del self.message_queues[myActSock][0]
                        next_msg = message_queues[myActSock].get_nowait()
                        if myActSock == self.server:
                            myRcv = 'P>S' 
                            
                        else:
                            myRcv = 'P>C'
                        
                        self._proto.addEntry('INFO    ','Send-Message to : {}'.format(myActSock))
                        if (self.server_url):
                            self._proto.addEntry('INFO    ','Queue-Length-CLIENT : {} / Queue-Length-SERVER : {}'.format(len(self.message_queues[self.client]),len(self.message_queues[self.server])))
                        #myActSock.sendall(next_msg)
                        while len(next_msg) > 0:
                            sent = myActSock.send(next_msg)
                            if sent < len(next_msg):
                                next_msg = next_msg[sent:]
                            else:
                                break
                        try:
                            self._proto.addEntry('INFO    ',next_msg.decode())
                        except:
                            pass
                        self._proto.addEntry('INFO    ',"Block-length : {}".format(len(next_msg.decode())))
                        self._proto.addEntry('INFO '+myRcv,'sending DATA to {}'.format(myActSock.getpeername()[0]))
                        self.logger.debug('sending DATA to {}'.format(myActSock.getpeername()[0]))
                    

                    except err as Exception:
                        self._proto.addEntry('ERROR   ','While sending to Socket : {}'.format(err))
                        self.stop('While sending to Socket : {}'.format(err))
                    
                else:
                    pass
                    #self._proto.addEntry('INFO    ','No Data for writable Socket : {}'.format(myActSock))
            '''
            for myActSock in exceptional:
                    self._proto.addEntry('ERROR   ','Exception on Socket : {}'.format(myActSock))
                    self.stop("Exception from Socket : {}".format(myActSock))
                
                

        self.Stop("not Alive any longer")
    
    def _handleServerBlock(self, mySocket):
        try:
            if self.server_url:
                serverblock = b''
                if self.debug_level > 5:
                    self._proto.addEntry('INFO    ','Start - Read-Message from : {}'.format(mySocket.getpeername()[0]))
                while True:
                    serverdata = mySocket.recv(self.BUFF_SIZE_SERVER)
                    if serverdata:
                        serverblock += serverdata
                    if len(serverdata) < self.BUFF_SIZE_SERVER:
                        break
                if self.debug_level > 5:
                    self._proto.addEntry('INFO    ','Stop - Read-Message from : {}'.format(mySocket.getpeername()[0]))
                
            if serverblock:
                try:
                    if self.debug_level > 5:
                        self.Server_Block_Length.append(len(serverblock))
                        self._proto.addEntry('INFO (P)','Block-Length for Read-Server: {}'.format(len(serverblock)))
                    #if len(serverblock) > 16384:
                except:
                    pass
                
                try:
                    self.proxied_bytes += len(serverblock)
                    #self.sh.AlexaCamProxy4P3.cams.Cams[self.actCam.proxied_Url].proxied_bytes += len(serverblock)
                    #self.logger.error("added proxied bytes")
                except Exception as err:
                    self.logger.error("Server-Block inconsistent")
                    self._proto.addEntry('INFO    ',"Server-Block inconsistent during adding proxied bytes")
                    
                try:
                    if "\r\n" in serverblock.decode():
                        if self.debug_level > 5:
                            self._proto.addEntry('INFO S>P',serverblock.decode())
                        if 'Content-Type: application/sdp' in serverblock.decode() and 'Content-length' in serverblock.decode():
                            self.handshake = 1      # got SDP
                        if 'SETUP' in serverblock.decode() and 'Transport' in serverblock.decode():
                            self.handshake = 2      # got SETUP
                        if 'PLAY' in serverblock.decode() and 'Session' in serverblock.decode():
                            self.handshake = 3      # got PLAY                            
                except:
                    self.Sender.message_queues[self.client].put(serverblock)
                    return

                

                
                try:
                    if ( not self.server_auth and "WWW-Authenticate" in serverblock.decode()):
                        if self.debug_level > 5:
                            self._proto.addEntry('INFO S>P',"Got WWW-Authenticate from Camera\r\n"+ serverblock.decode())
                        # inject Authorization in self.server_describe
                        if (self.server_describe != ""):
                            myResponse = self.server_add_authorization(serverblock.decode(),self.server_describe.decode())
                            myResponse = self._inject_line(self.server_describe, self.authenticate)
                            myResponse = self._inject_sequence_no(myResponse,self.server_last_Cseq)
                            self.server_last_Cseq += 1
                            #self.server.sendall(myResponse)
                            #self.message_queues[self.server].append(myResponse)
                            #self.message_queues[self.server].put(myResponse)
                            #self.Sender.message_queues[self.server].put(myResponse)
                            self.send_immendiate(self.server, myResponse)
                            if self.debug_level > 5:
                                self._proto.addEntry('INFO P>S',"Send Authorization to Camera\r\n"+ myResponse.decode())
                            self.server_auth = True
                            return
                    
                except Exception as err:
                    self._proto.addEntry('ERROR   ',"While Authentication".format(err))
                    pass
                    
                    
                
                # send data from Server to Client
                try:
                    if "\r\n" in serverblock.decode():
                        if ('Content-length' in serverblock.decode()):
                            self._proto.addEntry('INFO (X)','Before-'+serverblock.decode())
                        serverblock = self._inject_sequence_no(serverblock, self.client_last_Cseq)
                except:
                    #self._proto.addEntry('ERROR   ',"ERROR while injecting last client sequence")
                    pass
                
                try:
                    if "\r\n" in serverblock.decode() and self.debug_level > 5:
                        self._proto.addEntry('INFO P>C',serverblock.decode())
                        #self._proto.addEntry('INFO    ',"Block-length : {}".format(len(serverblock.decode())))
                except:
                    pass

                    
                #self.message_queues[self.client].append(serverblock)
                #self.message_queues[self.client].put(serverblock)
                #self.Sender.message_queues[self.client].put(serverblock)
                self.send_immendiate(self.client, serverblock)
                #myErg = self.client.sendall(serverblock)
                #if myErg != None:
            else:
                self.stop("Server Hang Up")
                
    
        except Exception as err:
            self.logger.info("ProxyCam4AlexaP3: Server disconnected right now not connected - {}".format(err))
            self.stop('Server-hang up')

    def _handleClientBlock(self, mySocket):
        try:
            self.peer = mySocket.getpeername()[0]
        except Exception as err:
            self.logger.warning("Problem by by getting Peer-Name")

        clientblock = b''
        while True:
            clientdata = mySocket.recv(self.BUFF_SIZE_CLIENT)
            if clientdata:
                clientblock += clientdata
            if len(clientdata) < self.BUFF_SIZE_CLIENT:
                break

        
        
        if clientblock:
            if self.debug_level > 5:
                self._proto.addEntry('INFO (P)','Block-Length for Read-Client in: {}'.format(len(clientblock)))
            try:
                if "\r\n" in clientblock.decode():
                    if self.debug_level > 5:
                        self.logger.debug("ProxyCam4AlexaP3: Client-Message-{}".format(str(clientblock.decode())))
                        self._proto.addEntry('INFO C>P','Client-Message-{}'.format(str(clientblock.decode())))
                        self._proto.addEntry('INFO    ',"Block-length : {}".format(len(clientblock.decode())))
                
                    try:
                        self.client_last_Cseq = self._get_sequence_no(clientblock)
                    except:
                        pass
            except:
                # Only Stream-Infos add to qeue and return
                #self.message_queues[self.server].put(clientblock)
                self.Sender.message_queues[self.server].put(clientblock)
                return
            
                
            if (self.Authorization_send == False):    
                if 'DIGEST' in self.proxy_auth_type:
                    AuthResponse = self.CreateDigestAuthResponse().encode()
                    AuthResponse = self._inject_sequence_no(AuthResponse,self.client_last_Cseq)
                    #self.message_queues[self.client].put(AuthResponse)
                    #self.Sender.message_queues[self.client].put(AuthResponse)
                    #self.message_queues[self.client].append(AuthResponse)
                    #self.client.sendall(AuthResponse)
                    self.send_immendiate(self.client, AuthResponse)
                    self.Authorization_send = True
                    if self.debug_level > 5:
                        self.logger.debug(self.CreateDigestAuthResponse())
                        self._proto.addEntry('INFO P>C',AuthResponse.decode())
                    return
                elif 'BASIC' in self.proxy_auth_type:
                    AuthResponse =self.CreateBasicAuthResponse().encode()
                    AuthResponse = self._inject_sequence_no(AuthResponse,self.client_last_Cseq)
                    self.send_immendiate(self.client, AuthResponse)
                    #self.Sender.message_queues[self.client].put(AuthResponse)
                    #self.message_queues[self.client].put(AuthResponse)
                    #self.message_queues[self.client].append(AuthResponse)
                    #self.client.sendall(AuthResponse)
                    self.Authorization_send = True
                    if self.debug_level > 5:
                        self.logger.debug(self.CreateBasicAuthResponse())
                        self._proto.addEntry('INFO P>C',AuthResponse.decode())
                    return

                
            # Authorization arrives
            if ('Authorization:' in clientblock.decode() and not self.Credentials_Checked):

                self.Credentials_Checked = self.CheckAuthorization(clientblock.decode('utf-8'))
                if not self.Credentials_Checked:
                    ForbiddenResponse =self.CreateForbiddenResponse().encode()
                    ForbiddenResponse = self._inject_sequence_no(ForbiddenResponse,self.client_last_Cseq)
                    #self.client.sendall(ForbiddenResponse)
                    #self.message_queues[self.client].append(ForbiddenResponse)
                    #self.message_queues[self.client].put(ForbiddenResponse)
                    #self.Sender.message_queues[self.client].put(ForbiddenResponse)
                    self.send_immendiate(self.client, ForbiddenResponse)
                    if self.debug_level > 5:
                        self.logger.debug(self.CreateForbiddenResponse())
                        self._proto.addEntry('INFO P>C',ForbiddenResponse.decode())
                    self.stop('Authorization failed 403')
                    self._proto.addEntry('INFO P>C','Authorization failed 403')
                    return
                else:
                    if self.debug_level > 5:
                        self._proto.addEntry('INFO P>C','Client - Authorization OK')
            
            # Keep Describe to Server in mind
            if ('DESCRIBE' in clientblock.decode() and self.server_describe == "" and not 'OPTIONS' in clientblock.decode()):
                self.server_describe = clientblock
                if self.debug_level > 5:
                    self._proto.addEntry('INFO    ',"reminded DESCRIBE from Client\r\n"+self.server_describe.decode())            
            
            
            
                

                
            
            
                   
            # Send data to Server if connected
                                        
            try:
                if self.Credentials_Checked and "\r\n" in clientblock.decode():
                    if ('Authorization:' in clientblock.decode()):
                        myClientBlock = self.DeleteAuthoriziation(clientblock.decode())
                        clientblock = myClientBlock.encode()
                         
                    

                    try:
                        self._inject_sequence_no(clientblock,self.server_last_Cseq)
                        self.server_last_Cseq += 1
                        if (self.authenticate != ""):
                            clientblock = self._inject_line(clientblock, self.authenticate)
                    except err as Exception:
                        if self.debug_level > 5:
                            self._proto.addEntry('ERROR   ',"While inject_squence in Clientblock/add authenticate {}".format(err))
                        pass
                    
                    if not self.server_url and self.Credentials_Checked == True:
                        try:
                            try:
                                serverUrl, serverport,self.actCam =self.getUrl(clientblock.decode())
                                if serverUrl == False:
                                    # found no Cam
                                    self.stop('Found no Cam !!')
                            except Exception as err:
                                self.logger.debug("Error while parsing real URL")
                                self.stop('Found no Cam !!')
                            try:
                                try:
                                    self._proto.addEntry('INFO    ',"Start setting up Server-Connection")
                                    self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                    self.server.connect((serverUrl, int(serverport)))
                                    self.server.setblocking(0)
                                    self.server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,1)
                                    self.mysocks.append(self.server)
                                    self.Sender.socks_write.append(self.server)
                                    self.Sender.server = self.server
                                    self.Sender.message_queues[self.server] = queue.Queue()
                                    self._proto.addEntry('INFO    ',"Complete setting up Server-Connection")
                                    #self.message_queues[self.server] = queue.Queue()
                                    self.server_url = True
                                    if self.debug_level > 5:
                                        self.logger.debug("ProxyCam4AlexaP3: connected to Camera")
                                        self._proto.addEntry('INFO    ',"ProxyCam4AlexaP3: connected to Camera")

                                except:
                                    self.logger.warning("could not connected to Camera : {}".format(serverUrl))
                                    self._proto.addEntry('ERROR   ',"could not connected to Camera : {}".format(serverUrl))
                                    self.stop("not Connection to Camera")
                            except Exception as err:
                                self.logger.debug("not able to connect to Server-{}".format(err))
                                self.stop('Exception see log-file')
                            
                        except Exception as err:
                            self.logger.debug("got no ServerUrl / ServerPort / ActualCam :{}".format(err))
                            self.stop('Exception see log-file')
                    
                    
                    if ('DESCRIBE' in clientblock.decode() and self.server_describe != "" and self.server_url):
                        # Now inject URL
                        self.server_describe = self._inject_sequence_no(clientblock, self.server_last_Cseq)
                        self.server_describe = self.InjectRealUrl(self.server_describe)
                        if self.server_describe == False:
                            self.stop("Error while InjetRealURL")
                        if self.debug_level > 5:
                            self._proto.addEntry('INFO    ',"parsed DESCRIBE from Client\r\n"+self.server_describe.decode())
                        injectedUrl = self.server_describe
                        if self.debug_level > 5:
                            self.logger.debug("Client-Msg-injected : {}".format(str(injectedUrl.decode())))
                            self._proto.addEntry('INFO    ',"Client-Msg-injected\r\n{}".format(str(injectedUrl.decode())))
                        clientblock = injectedUrl
                    
                    
                    # Inject the User-Agent
                    clientblock = self._inject_user_agent(clientblock)

                    self.send_immendiate(self.server, clientblock)
                    #self.message_queues[self.server].put(clientblock)
                    #myErg = self.server.sendall(clientblock)
                    #if myErg != None:
                    
                    if "\r\n" in clientblock.decode():
                        if self.debug_level > 5:
                            self._proto.addEntry('INFO P>S',clientblock.decode())
                        #self._proto.addEntry('INFO    ',"Block-length : {}".format(len(clientblock.decode())))
            except err as Exception:
                self.logger.debug("Error while server-send {}".format(err))

                
            if 'TEARDOWN' in clientblock.decode():
                #pass
                self.stop('TEARDOWN')


        else:
            self.stop('Client-hang up')
            if self.handshake == 1:
                self._proto.addEntry('ERROR   ','Client hang up after SDP-Information - perhaps you have specified a wrong Video/Audio-Setting to your Alexa-Device')

    
    def send_immendiate(self,sock2send,next_msg):
        time1 = datetime.now()
        blocklength = len(next_msg)
        if self.debug_level > 10:
            self._proto.addEntry('INFO (I)',self.name + ' - ' + str(next_msg))
        while len(next_msg) > 0:
            sent = sock2send.send(next_msg)
            if sent < len(next_msg):
                next_msg = next_msg[sent:]
            else:
                break
        if self.debug_level > 5:
            time2 = datetime.now()
            sendtime = time2-time1
            self._proto.addEntry('INFO (I)',self.name+' - send-duration {} - Send-Message to : {} - block-length : {}'.format(sendtime, sock2send.getpeername()[0],blocklength))


    def getUrl(self, request):
        port = ''
        webserver = ''
        # parse the first line
        first_line = request.split('\n')[0]

        # get url
        url = first_line.split(' ')[1]
        http_pos = url.find("://")  # find pos of ://
        if (http_pos == -1):
            temp = url
        else:
            temp = url[(http_pos + 3):]  # get the rest of url

        temp=url.split("/")[-1]    
        myCam = None
        try:
            myCam = self.cams.get(temp)
        except:
            pass
        
        if myCam == None:
            try:
                myCam = self.cams.getCambyUUID(temp)
            except:
                pass
        # Still not found the correct Camera
        if myCam == None:
            self._proto.addEntry('ERROR   ',"Found no Camera for {} while getting URL".format(temp))
            return False,False,False
        
        myCam.last_Session_Start = datetime.now()
        myCam.last_Session = myCam.last_Session_Start
        myCam.Sessions_total += 1
        temp=myCam.real_Url
        try:
            port_pos = temp.find(":")  # find the port pos (if any)
    
            # find end of web server
            webserver_pos = temp.find("/")
            if webserver_pos == -1:
                webserver_pos = len(temp)
    
            webserver = ""
            port = -1
            if (port_pos == -1 or webserver_pos < port_pos):
    
                # default port
                port = 554
                webserver = temp[:webserver_pos]
    
            else:  # specific port
                port = int((temp[(port_pos + 1):])[:webserver_pos - port_pos - 1])
                webserver = temp[:port_pos]
        except:
            self._proto.addEntry('ERROR   ',"Error while parsing REAL-URL : {}".format(myCam.real_Url))
            self.logger.error("Error while parsing REAL-URL : {}".format(myCam.real_Url))
            return False,False,False
        
        webserver = "{}".format(webserver)
        try:
            myHost = socket.gethostbyname(webserver)
            if (myHost != webserver):
                if self.debug_level > 5:
                    self._proto.addEntry('INFO    ',"resolved IP {} for Hostname : {}".format(myHost,webserver))
                webserver = myHost
        except:
            self._proto.addEntry('ERROR   ',"Could not resolve IP-Adress for {}".format(webserver))
            self.logger.error("Could not resolve IP-Adress for {}".format(webserver))
            return False,False,False
        if port == "": 
            port = 554
        self.logger.debug("got real Webserver-{}-".format(webserver))        
        return webserver, port, myCam

        
    def InjectRealUrl(self,orgRequest):
        readableRequest = orgRequest.decode()
        first_line = readableRequest.split('\n')[0]

        url = first_line.split(' ')[1]
        http_pos = url.find("://")  # find pos of ://
        if (http_pos == -1):
            temp = url
        else:
            temp = url[(http_pos + 3):]  # get the rest of url
        
            
        myCam = None
        try:
            myCam = self.cams.get(temp)
        except:
            pass
        
        if myCam == None:
            try:
                temp=url.split("/")[len(url.split("/"))-1]
                myCam = self.cams.getCambyUUID(temp)
            except:
                pass
        # Still not found the correct Camera
        if myCam == None:
            self._proto.addEntry('ERROR   ',"Found no Camera for {} while injecting real-URL".format(temp))
            return False
        
        
        NewUrl = "rtsp://%s" % (myCam.real_Url)
        
        
        newStreamInfo = readableRequest.replace(url,NewUrl)
        # deleting Authorization 
        newStreamInfo = self.DeleteAuthoriziation(newStreamInfo)
        
        try:
            myResponse = newStreamInfo.encode()#encoding='UTF-8',errors='strict')
        except Exception as err:
            self.logger.debug("Encoding Error :{}".format(err))            
        
        
        return myResponse
    
    def DeleteAuthoriziation(self,myRequest):
        #if myRequest.find("Authorization") < 0:
        #    return myRequest
        
        NewResponse = ""
        
        myLines = myRequest.splitlines()
        for line in myLines:
            if line.find("Authorization") < 0:
                NewResponse += line+"\r\n"
        
        #NewResponse += "\r\n"
        return NewResponse
        
            
    
    def CheckAuthorization(self,Request):
        
        PropValues ={}
        PropValues['qop']=""
        PropValues['realm']=""
        PropValues['nonce']=""
        PropValues['uri']=""
        PropValues['cnonce']=""
        PropValues['nc']=""
        PropValues['username']=""
        PropValues['password']=""
        PropValues['method']=""
        PropValues['algorithm']=""
        PropValues['entity_body']=""
        if self.debug_level > 5:
            self._proto.addEntry('INFO    ',"CheckAuthorization\r\n" + Request)
        
        
        if Request.find("Authorization") < 0:
            return False 
        
        myLines=Request.splitlines()
        for line in myLines:
            if line.find('RTSP/1.0') >=0:
                helpFields = line.split(" ")
                PropValues['method']=helpFields[0].strip()
            if line.find("Authorization") >= 0:
                break
            
        if self.debug_level > 5:        
            self._proto.addEntry('INFO    ',"found Method : {}".format(PropValues['method']))                
        # no Authorization found
        if len(line) <= 5:
            return False
        
        
         
        AuthorizationType = ''
        nonce = ''
        
        myFields = line.split(",")
        for field in myFields:
            if field.find("Authorization")>=0:
                # Line with Authorization type and nonce
                helpFields = field.split(" ")
                nonce=helpFields[2].split("=")
                nonce=nonce[1].replace('"','')                 
                PropValues["nonce"] = nonce
                AuthorizationType = helpFields[1]
                continue
            key,value = field.split('=')
            value = value.replace('"','')
            key=key.strip()
            PropValues[key]= value
        PropValues['password']= self.pwd
        if AuthorizationType.upper() == 'DIGEST':
            myResponse = self.CalcHttpDigest(PropValues["qop"],
                                             PropValues["realm"],
                                             PropValues["nonce"],
                                             PropValues["uri"],
                                             PropValues["cnonce"],
                                             PropValues["nc"],
                                             PropValues["username"],
                                             PropValues["password"],
                                             PropValues["method"],
                                             PropValues["algorithm"],
                                             PropValues["entity_body"])    
            if myResponse == PropValues["response"]:
                return True
        
        elif AuthorizationType.upper() == 'BASIC':
            return self.CheckUser(Request)
    
           
    
    def CalcHttpDigest(self,
                       qop,realm,
                       nonce,
                       uri,
                       cnonce,
                       nc,
                       username,
                       password,
                       method,
                       algorithm,
                       entity_body):
        
        # Calc HA1
        ha1 = hashlib.md5()
        if algorithm == "MD5" or algorithm == "":
            ha=username+":"+realm+":"+password
            ha1.update(ha.encode('utf-8'))
        elif algorithm == "MD5-sess":
            helpMd5 = hashlib.md5()
            ha=username+":"+realm+":"+password
            helpMd5.update(ha.encode('utf-8'))
            ha=helpMd5.hexdigest()+":"+nonce+":"+cnonce
            ha1.update(ha.encode('utf-8'))
            
        # Calc HA2
        ha2 = hashlib.md5()
        if qop == "auth" or qop == '':
            ha=method+":"+uri
            ha2.update(ha.encode('utf-8'))
        else:
            helpMd5 = hashlib.md5()
            helpMd5.update(entity_body.encode('utf-8'))
            ha=method+":"+uri+":"+helpMd5.hexdigest()
            ha2.update(ha.encode('utf-8'))
        
        # Everything prepared now calc final
        response = hashlib.md5()
        if qop == "auth" or qop == 'auth-int':
            ha=ha1.hexdigest()+":"+nonce+":"+nc+":"+cnonce+":"+qop+":"+ha2.hexdigest()
            response.update(ha.encode('utf-8'))
        else:
            ha=ha1.hexdigest()+":"+nonce+":"+ha2.hexdigest()
            response.update(ha.encode('utf-8'))
            
        return response.hexdigest()
    
    
    def CheckUser(self, request):
        try:
            request = request.splitlines()
            for line in request:
                if "Authorization" in line:
                    request = line
                    break
            Credentials = request.split(" ")
            Credentials = base64.b64decode(Credentials[2]).decode()
            Credentials = Credentials.split(":")
            User = Credentials[0]
            Pwd =Credentials[1]
            
            if User == self.proxy_credentials.split(":")[0] and Pwd == self.proxy_credentials.split(":")[1]:
                return True
            else:
                return False
        
        except Exception as err:
            self.logger.error("Problem while parsing User-Credentials")
            return False
            
    def server_add_authorization(self, serverblock, myDescribe):
        PropValues ={}
        PropValues['qop']=""
        PropValues['realm']=""
        PropValues['nonce']=""
        PropValues['uri']=""
        PropValues['cnonce']=""
        PropValues['nc']=""
        PropValues['username']=""
        PropValues['password']=""
        PropValues['method']=""
        PropValues['algorithm']=""
        PropValues['entity_body']=""
        
        # prepare Reponse-Fields
        AuthorizationType = ''
        nonce = ''
        newResponse=[]
        newResponseArray = myDescribe.split("\r\n")
        for line in newResponseArray:
            if line.strip() != "":
                if "CSEQ:" in line.upper():
                    SequenceNo = int(line.split(":")[1])
                    line = "CSeq: "+str(SequenceNo+1)
                newResponse.append(line+"\r\n")
                
        # Get method
        myLines=myDescribe.splitlines()
        for line in myLines:
            if line.find('RTSP/1.0') >=0:
                helpFields = line.split(" ")
                PropValues['method']=helpFields[0].strip()
                PropValues['uri']=helpFields[1].strip()

        myLines=serverblock.splitlines()
        for line in myLines:            
            if line.find("WWW-Authenticate") >= 0:
                break
        
        
        myLines = line.split(",")
        for myFields in myLines:
            if myFields.find("WWW-Authenticate")>=0:
                # Line with Authorization type and nonce
                helpFields = myFields.split(" ")
                AuthorizationType = helpFields[1]
                myValue=line.find('realm="')+7
                realm = line[myValue:]
                myValue = realm.find('"')
                realm=realm[:myValue]
                
                
                
                PropValues["realm"] = realm
                continue
            if myFields.find("nonce")>=0:
                nonce=myFields.split("=")
                nonce = nonce[1].replace('"', '')
                PropValues["nonce"] = nonce
            

        PropValues['password']= self.actCam.pwd
        PropValues['username']= self.actCam.user
                
        if AuthorizationType.upper() == 'DIGEST':
            myNonce = self.CalcHttpDigest(PropValues["qop"],
                                             PropValues["realm"],
                                             PropValues["nonce"],
                                             PropValues["uri"],
                                             PropValues["cnonce"],
                                             PropValues["nc"],
                                             PropValues["username"],
                                             PropValues["password"],
                                             PropValues["method"],
                                             PropValues["algorithm"],
                                             PropValues["entity_body"])
            
            myAuth = 'Authorization: Digest username="'+PropValues["username"]+'", realm="'+PropValues["realm"]+'", nonce="'+ PropValues["nonce"] +'", uri="'+PropValues["uri"]+'", response="'+myNonce+'"'# +"\r\n"

            newResponse.append(myAuth)
        
        elif AuthorizationType.upper() == 'BASIC':
            myCredentials = (self.actCam.user+":"+self.actCam.pwd)
            myCredentials = base64.b64encode(myCredentials.encode('utf-8')).decode()
            myAuth = 'Authorization: Basic '+ myCredentials
            newResponse.append(myAuth)
            
        myResponse = ""
        for line in newResponse:
            myResponse += line
            
        self.authenticate = myAuth
        
        return myResponse
    
    
    
    def _inject_line(self,block_to_decode,line2inject):
        myNewBlock = ""
        myNewArray = []
        for line in block_to_decode.decode().split("\r\n"):
            myNewArray.append(line)
        ArrayCount = len(myNewArray)
        myNewArray.insert(2, line2inject)
        myNewArray = myNewArray[:-1]
        for line in myNewArray:
            myNewBlock += line +"\r\n"
        
        
        NewBlock = myNewBlock.encode()
        return NewBlock
    
    
    def _get_sequence_no(self,block_to_decode):
        for line in block_to_decode.decode().split("\r\n"):
            if ("CSEQ" in line.upper()):
                actSequenceNo = int(line.split(":")[1])
                break
        return actSequenceNo
        
    def _inject_sequence_no(self,block_to_decode,act_sequence_no):
        myNewBlock = ""
        myNewArray = []
        length_2_replace = ''
        for line in block_to_decode.decode().split("\r\n"):
            if ("CSEQ" in line.upper()):
                line ="CSeq: " + str(act_sequence_no) + " "
            
            if ("Range: npt=0.000-" in line):
                line ='Range: npt=now-'
            
            if ("a=range:npt=0-" in line):
                line ='a=range:npt=now-'
            
                 
            if ("CONTENT-LENGTH" in line.upper()):
                length_2_replace = line
                pass
            
            myNewArray.append(line)
        
        myNewArray = myNewArray[:-1]
        for line in myNewArray:
            myNewBlock += line +"\r\n"
        
        if length_2_replace != '':
            newBlockLength = "Content-length: " +str(len(myNewBlock[myNewBlock.find("\r\n\r\n"):])-4)
            myNewBlock = myNewBlock.replace(length_2_replace,newBlockLength)
        NewBlock = myNewBlock.encode()
        return NewBlock
        
        
    def _inject_user_agent(self,block_to_decode):
        newAgent = 'User-Agent: LibVLC/3.0.6 (LIVE555 Streaming Media v2016.11.28)'
        myNewBlock = ""
        myNewArray = []
        for line in block_to_decode.decode().split("\r\n"):
            if ("USER-AGENT" in line.upper()):
                line =newAgent
            
            myNewArray.append(line)
        
        myNewArray = myNewArray[:-1]
        for line in myNewArray:
            myNewBlock += line +"\r\n"
        
        NewBlock = myNewBlock.encode()
        return NewBlock
