# https://developer.amazon.com/public/solutions/alexa/alexa-skills-kit/docs/steps-to-create-a-smart-home-skill
# https://developer.amazon.com/public/solutions/alexa/alexa-skills-kit/docs/smart-home-skill-api-reference
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






class ThreadedServer(threading.Thread):
    def __init__(self, logger,port, video_buffer,cert_path,cert_path_key, Cams, ClientThreads,proxyUrl,path_user_file,proxy_credentials,proxy_auth_type):
        threading.Thread.__init__(self)
        self.logger = logger
        self.port = int(port)
        self.video_buffer = int(video_buffer)
        self.cert_path = cert_path
        self.cert_path_key = cert_path_key
        self.ClientThreads = ClientThreads
        self.sock = None
        self.running = False
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
        self.running= False
        self.logger.info("ProxyCamAlexaP4: set running to false")
        self.sock.shutdown(socket.SHUT_RDWR)
        self.logger.info("ProxyCamAlexaP4: shutdown socket")
        self.sock.close()
        self.logger.info("ProxyCamAlexaP4: closed socket")
    
        
    def run(self):
        self.logger.info("ProxyCamAlexaP4: service starting")
        if self.FirstRound:
                if (self.proxyUrl != ''):
                    self.myIP = self.GetMyIP(self.proxyUrl)
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.bind(('', self.port))
                self.sock.listen(5)
                self.FirstRound=False
                self.running= True
                #================================
                # SSL-Settings
                #================================
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                # add Certificate to context
                context.load_cert_chain(self.cert_path, self.cert_path_key)  
                # add ciphers to context
                context.set_ciphers(self.cert_ciphers)
        aktThread = 0        
        while self.running:
            client, address = self.sock.accept()
            try:
                conn = context.wrap_socket(client, server_side=True)
                # Check if only own IP is allowed
                if (self.proxyUrl != ''):
                    self.myIP = self.GetMyIP(self.proxyUrl)
                    reqAdress = address[0]
                    if self.myIP != reqAdress:
                        client.shutdown(socket.SHUT_RDWR)
                        client.close()
                        continue
            except Exception as err:
                self.logger.error("ProxyCam4AlexaP3: SSL-Error - {} ".format(err))
                client.shutdown(socket.SHUT_RDWR)
                client.close()
                continue

            client.settimeout(5)
 
            try:
                # Clean up old Threads
                for t in self.ClientThreads:
                    if t.alive == False:
                        try:
                            t.actCam.proxied_bytes +=t.proxied_bytes
                            self.ClientThreads.remove(t)
                        except:
                            pass
                        
                self.ClientThreads.append(listenProxy(conn,address,self.logger,self.Cams,self.video_buffer,self.path_user_file,self.proxy_credentials,self.proxy_auth_type))
                aktThread +=1
                if aktThread > 99999:
                    aktThread = 1
                lastAdded = len(self.ClientThreads )-1
                NewThreadName ="CamThread-{0:06d}".format(aktThread)
                self.ClientThreads[lastAdded].name = NewThreadName

                self.logger.info("ProxyCam4AlexaP3: Added Thread %s" % NewThreadName)
                self.ClientThreads[lastAdded].daemon = True
                self.ClientThreads[lastAdded].start()
                #self.ClientThreads[lastAdded].join()        ### ?????????????????????????????

            except Exception as err:
                self.logger.info("ProxyCam4AlexaP3: NewThreadError - {}".format(err))
            
            self.logger.debug("ProxyCam4AlexaP3: new Thread added, total Threads:{} ".format(str(len(self.ClientThreads ))))

            
            
class listenProxy(threading.Thread):
    def __init__(self, client, address,logger,cams,videoBuffer=524280, path_User_File = '',proxy_credentials='',proxy_auth_type='NONE'):
        threading.Thread.__init__(self)
        self.logger = logger
        self.mysocks = []
        self.client = client
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.mysocks.append(client)
        self.mysocks.append(self.server)
        self.server_url = False
        self.alive = False
        self.serversend = 0
        self.BUFF_SIZE_SERVER=videoBuffer
        self.cams = cams
        self.proxied_bytes = 0
        self.peer = ''
        self.actCam = None
        self.last_Session_Start = datetime.now()
        self.path_User_File = path_User_File
        self.Credentials_Checked = False
        self.Authorization_send = False
        self.proxy_credentials=proxy_credentials
        self.proxy_auth_type=proxy_auth_type
        self.nonce = hashlib.sha1(str(random()).encode()).hexdigest()
        


        
    def stop(self, txtInfo = ''):
        if txtInfo=='Server socket is dead':
            pass
        self.logger.debug("ProxyCam4AlexaP3: Cam Thread stopped")
        self.mysocks.remove(self.client)
        self.mysocks.remove(self.server)
        try:
            self.client.shutdown(socket.SHUT_RDWR)
            self.client.close()
        except Exception as err:
            self.logger.debug("ProxyCam4AlexaP3: Cam Thread cannot close client-socket - {}".format(err))
        try:
            self.server.shutdown(socket.SHUT_RDWR)
            self.server.close()
        except Exception as err:
            self.logger.debug("ProxyCam4AlexaP3: Cam Thread cannot close Server-socket-{}".format(err))
        self.logger.debug("ProxyCam4AlexaP3: Cam Thread stopped - %s" % txtInfo)
        self.actCam.proxied_bytes +=self.proxied_bytes
        try:
            self.actCam.last_Session_End = datetime.now()
            duration_sec = mktime(self.actCam.last_Session_End.timetuple()) - mktime(self.actCam.last_Session_Start.timetuple())
            self.actCam.last_Session_duration = str(timedelta(seconds=duration_sec))
        except:
            self.logger.debug("ProxyCam4AlexaP3: Problem during calculating duration-{}".format(err))
        self.alive = False
        #self.ClientThreads.remove(self)
        
    def Test(self):
        pass
         
    
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
        #AuthResp += 'WWW-Authenticate: Digest realm="Access2AlexaCam", nonce="'+self.nonce+'59dd520e1f9132c04ea6a45b80c4e4ed"\r\n\r\n'
       
        return AuthResp
    
    def CreateForbiddenResponse(self):
        actDate = datetime.now()
        fmtDate = actDate.strftime('Date: %a, %d %b %H:%M:%S %Z %Y\r\n')
        ForbidResp = 'RTSP/1.0 403 Forbidden\r\n' 
        ForbidResp += fmtDate
        
        return ForbidResp
        
    

        
    def run(self):
        BUFF_SIZE_CLIENT=4096
        BUFF_SIZE_SERVER=self.BUFF_SIZE_SERVER
        self.logger.info("ProxyCam4AlexaP3: Cam Thread startet")
        self.alive = True
        serverblock = b''
        clientblock = b''
        loopcount =0
                    
        while self.alive:
            if loopcount==50:
                #self.logger.debug("ProxyCam4AlexaP3: Cam Thread running in loop-{}".format(self._name))
                loopcount=0
            else:
                loopcount +=1
            # check if all sockets are online
            if not self.issocketvalid(self.client):
                self.stop('Client socket is dead')
                continue        # loop
            if not self.server and self.server_url: # and not self.issocketvalid(self.server) ???? When has state 107 passed ??? 
                self.stop('Server socket is dead')
                continue        # loop
            readable, writable, exceptional = select.select(self.mysocks, [], [])
            #self.logger.debug("Got readable socket")
            for myActSock in readable:
                if myActSock == self.server:
                    try:
                        if self.server_url:
                            serverblock = b''
                            while True:
                                serverdata = self.server.recv(BUFF_SIZE_SERVER)
                                if serverdata:
                                    serverblock += serverdata
                                if len(serverdata) < BUFF_SIZE_SERVER:
                                    break
                        if serverblock:
                            # send data from Server to Client
                            self.client.send(serverblock)
                            #if len(serverblock)<10000:
                            #    self.logger.info("Server-sends:{}".format(serverblock.decode()))
                            if self.actCam != None:
                                try:
                                    self.proxied_bytes += len(serverblock)
                                except Exception as err:
                                    self.logger.info("Server-Block inconsistent")
                            '''
                            self.serversend += 1
                            if self.serversend == 3:
                                self.logger.info("ProxyCam4AlexaP3: Time for Stop - three times got Server-Request")
                                print ("Time for Stop three times got Server-Request")
                            # That means :
                            # Cam send -> Describe OK
                            # Cam send -> Setup
                            # Cam send -> Play OK
                            # Now everything should ready to stream to client
                            '''
                    except:
                        self.logger.info("ProxyCam4AlexaP3: Server disconnected right now not connected")
                        pass
                elif myActSock == self.client:
                    try:
                        
                        try:
                            self.peer = self.client.getpeername()[0]
                        except Exception as err:
                            self.logger.info("Problem by by getting Peer-Name")

                        clientblock = b''
                        while True:
                            clientdata = self.client.recv(BUFF_SIZE_CLIENT)
                            if clientdata:
                                clientblock += clientdata
                            if len(clientdata) < BUFF_SIZE_CLIENT:
                                break

                        
                        
                        if clientblock:
                            self.logger.debug("ProxyCam4AlexaP3: Client-Message-{}".format(str(clientblock.decode())))
                            if not self.server_url:
                                try:
                                    try:
                                        serverUrl, serverport,self.actCam =self.getUrl(clientblock.decode())
                                    except Exception as err:
                                        self.logger.debug("Error while parsing real URL")
                                    
                                    if ('GET' in clientblock.decode() or self.Authorization_send == False):
                                        if 'DIGEST' in self.actCam.authorization:
                                            AuthResponse =self.CreateDigestAuthResponse().encode()
                                            self.client.sendall(AuthResponse)
                                            self.Authorization_send = True
                                            self.logger.debug(self.CreateDigestAuthResponse())
                                            continue
                                        elif 'BASIC' in self.actCam.authorization:
                                            AuthResponse =self.CreateBasicAuthResponse().encode()
                                            self.client.sendall(AuthResponse)
                                            self.Authorization_send = True
                                            self.logger.debug(self.CreateBasicAuthResponse())
                                            continue
                                        else:
                                            self.Authorization_send = True
                                            self.Credentials_Checked = True
                                            self.logger.debug('Allowed Access without Authorization NONE')
                                        
                                    
                                    # Authorization arrives
                                    if ('Authorization:' in clientblock.decode()) and not self.Credentials_Checked:
                                        self.Credentials_Checked = self.CheckAuthorization(clientblock.decode('utf-8'))
                                        if not self.Credentials_Checked:
                                            ForbiddenResponse =self.CreateForbiddenResponse().encode()
                                            self.client.sendall(ForbiddenResponse)
                                            self.logger.debug(self.CreateForbiddenResponse())
                                            self.stop('Authorization failed 403')
                                            continue
                                            
                                    if ('DESCRIBE' in clientblock.decode()):
                                        injectedUrl = self.InjectRealUrl(clientblock)

                                        #self.logger.debug("Client-Msg-org-{}".format(str(clientblock.decode())))                                        
                                        self.logger.debug("Client-Msg-new-{}".format(str(injectedUrl.decode())))
                                        clientblock = injectedUrl
                                        
                                    try:
                                        self.server.connect((serverUrl, int(serverport)))
                                        #self.server.settimeout(5)
                                        self.server_url = True
                                        self.logger.debug("ProxyCam4AlexaP3: connected to Server")
                                    except Exception as err:
                                        self.logger.debug("not able to connect to Server-{}".format(err))
                                        self.stop('Exception see log-file')
                                except Exception as err:
                                    self.logger.debug("got no ServerUrl / ServerPort / ActualCam :{}".format(err))
                                    self.stop('Exception see log-file')
                                   
                            # Send data to Server if connected
                                                        
                            try:
                                if self.Credentials_Checked:
                                    self.server.send(clientblock)
                            except Exception as err:
                                self.logger.debug("Error while server-send {}".format(err))

                                
                            if 'TEARDOWN' in clientblock.decode():
                                self.stop('TEARDOWN')
                            if 'PAUSE' in clientblock.decode():
                                self.stop('PAUSE')

                        else:
                            self.stop('Client-hang up')
                            continue        # loop
                            #self.logger.debug("ProxyCam4AlexaP3: Client-Message hang up")
                            #self.stop('Client-Message hang up')
                            #raise
                            #pass # error('Client disconnected')
                    except Exception as err:
                        self.logger.debug("ProxyCam4AlexaP3: Error in Client-Block-{}".format(err))
                        self.stop('Error in Client-Block')
                        pass
                        #return False

    def issocketvalid(self, socket_instance):
        """ Return True if this socket is connected. """
        if not socket_instance:
            return False

        try:
            socket_instance.getsockname()
        except socket.error as err:
            err_type = err.args[0]
            if err_type == errno.EBADF:  # 9: Bad file descriptor
                return False

        err_type = None
        try:
            socket_instance.getpeername()
        except socket.error as err:
            err_type = err.args[0]
        if err_type in [errno.EBADF, errno.ENOTCONN]:  # 9: Bad file descriptor.
            return False  # 107: Transport endpoint is not connected

        return True


    def getUrl(self, request):
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
        myCam = self.cams.get(temp)
        myCam.last_Session_Start = datetime.now()
        myCam.last_Session = myCam.last_Session_Start
        myCam.Sessions_total += 1
        temp=myCam.real_Url
        
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
        
        webserver = "{}".format(webserver)
        webserver = '192.168.178.9'
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
        myCam = self.cams.get(temp)
        if myCam.user == '' and myCam.pwd == '':
            NewUrl = "rtsp://%s" % (myCam.real_Url)
        elif myCam.pwd == '':
            NewUrl = "rtsp://" + myCam.user +"@"+ myCam.real_Url
        else:
            NewUrl = "rtsp://" + myCam.user + ":" + myCam.pwd + "@" + myCam.real_Url
        
        newStreamInfo = readableRequest.replace(url,NewUrl)
        # deleting Authorization 
        newStreamInfo = self.DeleteAuthorziation(newStreamInfo)
        
        try:
            myResponse = newStreamInfo.encode()#encoding='UTF-8',errors='strict')
        except Exception as err:
            self.logger.debug("Encoding Error :{}".format(err))            
        
        
        return myResponse
    
    def DeleteAuthorziation(self,myRequest):
        if myRequest.find("Authorization") < 0:
            return myRequest
        
        NewResponse = ""
        
        myLines = myRequest.splitlines()
        for line in myLines:
            if line.find("Authorization") < 0:
                NewResponse += line+"\r\n"
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
        
        
        
        if Request.find("Authorization") < 0:
            return False 
        
        myLines=Request.splitlines()
        for line in myLines:
            if line.find('RTSP/1.0') >=0:
                helpFields = line.split(" ")
                PropValues['method']=helpFields[0].strip()
            if line.find("Authorization") >= 0:
                break
            
                
                
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
             
        PropValues['password']= '8x+0bzT9'
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
    
    
    def replace(self,p, strsearch, newValue):
        if type(p) is dict:  
            if strsearch in p:
                tokenvalue = p[strsearch]
                p[strsearch] = newValue
                if not tokenvalue is None:
                 return tokenvalue
            else:
                for i in p:
                    tokenvalue = self.replace(p[i], strsearch,newValue)  
                    if not tokenvalue is None:
                        return tokenvalue
            
    
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
            request = request[2]
            Credentials = request.split(" ")
            Credentials = base64.b64decode(Credentials[2])
            Credentials = Credentials.decode("utf-8")
            Credentials = Credentials.split(":")
            User = Credentials[0]
            Pwd =Credentials[1]
            
            if len(self.path_User_File) == 0:
                return False
            
            proc = Popen(['htpasswd','-vb',self.path_User_File,User,Pwd], stdout=PIPE, stderr=PIPE)
            err, out = proc.communicate()
            exitcode = proc.returncode
            myString = out.decode()
            if myString.find("correct") > 0 :
                return True
            else:
                return False
        except Exception as err:
            self.logger.error("Problem while parsing User-Credentials")
