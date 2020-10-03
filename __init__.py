#!/usr/bin/env python3
# vim: set encoding=utf-8 tabstop=4 softtabstop=4 shiftwidth=4 expandtab
#########################################################################
#  Copyright 2019 <AndreK>                <andre.kohler01@googlemail.com>
#########################################################################
#  This file is part of SmartHomeNG.   
#

#
#  SmartHomeNG is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  SmartHomeNG is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with SmartHomeNG. If not, see <http://www.gnu.org/licenses/>.
#
#########################################################################
import os
import sys
import time
import base64

from datetime import datetime
from builtins import Exception
from time import mktime
from datetime import timedelta




from lib.module import Modules
from lib.model.smartplugin import *
from lib.item import Items

from .camdevice import CamDevices, Cam

import logging
import uuid
import json
import signal

from .service import ThreadedServer
from .proxy_handler import Sender
import queue

# Imports for TestSocket
import socket
import threading
import select
import ssl
import errno



class protocoll(object):
    
    log = []
    
    def __init__(self):
        pass
    
    def addEntry(self,type, _text ):
        myLog = self.log
        if (myLog == None):
            return
        try:
            if len (myLog) >= 2500:
                myLog = myLog[0:2499]
        except:
            return
        myEntries = _text.split('\r\n')
        entry_count = len(myEntries)-1
        while (entry_count >= 1):
            #if len(str(myEntries[entry_count])) > 0:
            myLog.insert(0,str("                   ")+'       ' + '       ' + '   '+str(myEntries[entry_count])+'«')
            entry_count += -1
        now = str(datetime.now())[0:24]
        myLog.insert(0,str(now)[0:24]+'  ' + str(type) + '  '+str(myEntries[0])+'«')
        self.log = myLog


class TestSocket(threading.Thread):
    def __init__(self,Proto, port, logger,video_buffer,sh_instance):
        threading.Thread.__init__(self)
        self._proto = Proto
        self.port = port
        self.logger = logger
        self.sh = sh_instance
        self._proto.addEntry('INFO    ',"Testsocket initialized")
        self.outgoing_socket = None
        self.incoming_socket = None
        self.mysocks = []
        self.alive = False
        self.message_queues = {}
        self.queue_counter = 0
        self.video_buffer = video_buffer
        self.Sender = None
        

    def run(self):
        self._proto.addEntry('INFO    ',"Testsocket started")
        self.logger.info("Testsocket started")
        self.alive = True
        self.cycle = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #self.sock.setblocking(0)
        self.sock.bind(('', 5001))
        self.sock.listen(5)
        wrappedSocket = None
        while self.alive:
            try:
                self.incoming_socket, address = self.sock.accept()
            except Exception as err:
                if (not "22" in str(err)):
                    self.logger.error('Listening socket for Testsocket could not be opened')
                    self._proto.addEntry('ERROR   ',"Testsocket : {}".format(err))
                raise 
            try:
                # Connect to AlexCamProxy4P3
                self.incoming_socket.setblocking(0)
                self.incoming_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,1)
                #self.mysocks.append(self.incoming_socket)
                #self.message_queues[self.incoming_socket] = []
                # Setup the Sender-Thread
                self.mysocks.append(self.incoming_socket)
                self.Sender = Sender( self._proto,self.logger,self.sh,self.message_queues)
                self.Sender.client = self.incoming_socket
                self.Sender.message_queues[self.incoming_socket] = queue.Queue()
                self.Sender.socks_write.append(self.incoming_socket)
                self.Sender.name = self.name + "-Sender"
                self.Sender.start()
                
                
                
                if wrappedSocket == None:
                    self.outgoing_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    # WRAP SOCKET
                    wrappedSocket = ssl.wrap_socket(self.outgoing_socket, do_handshake_on_connect=True)
                    # CONNECT AND PRINT REPLY
                    
                    wrappedSocket.connect(("127.0.0.1", self.port))
                    wrappedSocket.setblocking(0)
                    wrappedSocket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,1)
                    self.mysocks.append(wrappedSocket)
                    #self.message_queues[wrappedSocket] = []
                    self.Sender.server = wrappedSocket
                    self.Sender.message_queues[wrappedSocket] = queue.Queue()
                    self.Sender.socks_write.append(wrappedSocket)
                    
                
                #self.outgoing_socket.connect(("192.168.178.37", 443))
                
                #if not wrappedSocket in self.mysocks:
                #    self.mysocks.append(wrappedSocket)
                self.cycle = True
                while self.cycle:
                    #time.sleep(0.0001)       # give other Threads a Chance
                    readable, writable, exceptional = select.select(self.mysocks, [], self.mysocks,3)
                    for myActSock in readable :
    
                        if myActSock == wrappedSocket:
                            self._proto.addEntry('FLOW    ','Reading OUT')
                            outgoing_block = b''
                            while True:
                                outgoing_data = wrappedSocket.recv(self.video_buffer)
                                if outgoing_data:
                                    outgoing_block += outgoing_data
                                if len(outgoing_block) < self.video_buffer:
                                    break
                            
                            if len(outgoing_block) == 0:
                                try:
                                    self._proto.addEntry('ERROR   ','Testsocket got 0 Bytes from Server')
                                    self.Sender.socks_write.remove(wrappedSocket)
                                    self.mysocks.remove(wrappedSocket)
                                    wrappedSocket.close()
                                    wrappedSocket = None
                                    pass
                                except:
                                    pass
                                try:
                                    self.mysocks.remove(self.incoming_socket)
                                    self.Sender.socks_write.remove(self.incoming_socket)                                    
                                    self.incoming_socket.close()
                                except:
                                    pass    
                                self.Sender.stop()
                                self.cycle = False
                                break
                            self.Sender.message_queues[self.incoming_socket].put(outgoing_block)
                            #self.message_queues[self.incoming_socket].append(outgoing_block)
                            #self.incoming_socket.sendall(outgoing_block)
                        
                        if myActSock == self.incoming_socket:

                            incoming_block = b''
                            while True:
                                incoming_data = self.incoming_socket.recv(4096)
                                if incoming_data:
                                    incoming_block += incoming_data
                                if len(incoming_block) < 4096:
                                    break
                            self._proto.addEntry('INFO    ','Block-Length for Writing: {}'.format(len(incoming_block)))
                            if len(incoming_block) == 0:
                                try:
                                    self._proto.addEntry('ERROR   ','Testsocket got 0 Bytes from Client')
                                    wrappedSocket.sendall(b'TEARDOWN')
                                    self.mysocks.remove(wrappedSocket)
                                    wrappedSocket.close()
                                    wrappedSocket = None
                                    pass
                                except:
                                    pass
                                try:
                                    self.mysocks.remove(self.incoming_socket)
                                    self.incoming_socket.close()
                                except:
                                    pass
                                
                                self.Sender.stop()
                                self.cycle = False
                                break
                            #self.outgoing_socket.sendall(incoming_block)
                            #wrappedSocket.sendall(incoming_block)
                            #self._proto.addEntry('FLOW    ','Reading IN Length : {}'.format(len(incoming_block)) )
                            #self.message_queues[wrappedSocket].append(incoming_block)
                            self.Sender.message_queues[wrappedSocket].put(incoming_block)                                
                    for myActSock in exceptional:
                        wrappedSocket.close()
                        wrappedSocket = None
                        break
                    
            except Exception as err:
                try:
                    self.Sender.stop()
                    wrappedSocket.close()
                    wrappedSocket == None
                    pass
                except:
                    pass
                try:
                    self.incoming_socket.close()
                except:
                    pass
                #self.incoming_socket.shutdown(socket.SHUT_RDWR)
                
                #wrappedSocket=None
                self.mysocks = []
                continue
                
        
        
           
    def stop(self):
        self.cycle = False
        self._proto.addEntry('INFO    ',"Testsocket stopped")
        self.logger.info("Testsocket stopped")
        try:
            if self.Sender != None:
                self.Sender.stop()
        except Exception as err:
            self._proto.addEntry('ERROR   ',"Sender-Thread could not be stopped : {}".format(err))
            pass

        # close Listening Socket
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.logger.debug("Testsocket Listening-Socket shutdown OK")
            self._proto.addEntry('ERROR   ',"Listening-Socket shutdown correct")
        except Exception as err:
            self._proto.addEntry('ERROR   ',"Listening-Socket could not be shutdown : {}".format(err))
            pass

        try:
            self.sock.close()
            self.logger.debug("Testsocket Listening-Socket close OK")
            self._proto.addEntry('ERROR   ',"Listening-Socket close OK")
        except Exception as err:
            self._proto.addEntry('ERROR   ',"Listening-Socket could not be closed : {}".format(err))
            pass
        
        # close Incoming - Socket
        if (self.incoming_socket != None):
            try:
                self.incoming_socket.shutdown(socket.SHUT_RDWR)
                self.logger.debug("Testsocket Incoming-Socket shutdown OK")
            except Exception as err:
                self._proto.addEntry('ERROR   ',"Incoming-Socket could not be shutdown : {}".format(err))
                pass
    
            try:
                self.incoming_socket.close()
                self.logger.debug("Testsocket Incoming-Socket close OK")
            except Exception as err:
                self._proto.addEntry('ERROR   ',"Incoming-Socket could not be closed : {}".format(err))
                pass

        # close Outgoing - Socket
        if (self.outgoing_socket != None):
            try:
                self.outgoing_socket.shutdown(socket.SHUT_RDWR)
                self.logger.debug("Testsocket Outgoing-Socket shutdown OK")
            except Exception as err:
                self._proto.addEntry('ERROR   ',"Outgoing-Socket could not be shutdown : {}".format(err))
                pass
            
            try:
                self.outgoing_socket.close()
                self.logger.debug("Testsocket Outgoing-Socket close OK")
            except Exception as err:
                self._proto.addEntry('ERROR   ',"Outgoing-Socket could not be closed : {}".format(err))
                pass
        
        self.alive = False
    

        
        
class AlexaCamProxy4P3(SmartPlugin):
    PLUGIN_VERSION = '1.0.0'
    ALLOW_MULTIINSTANCE = False
    
    def __init__(self, sh, *args, **kwargs):
        self.sh = self.get_sh()
        self.logger = logging.getLogger(__name__)
        self.PATH_CERT = self.get_parameter_value('cert_path')
        self.PATH_PRIVKEY = self.get_parameter_value('cert_path_key') 
        self.proxyUrl = self.get_parameter_value('proxy_url')
        self.proxy_credentials=self.get_parameter_value('proxy_credentials')
        self.proxy_auth_type=self.get_parameter_value('proxy_auth_type')
        self.video_buffer = self.get_parameter_value('video_buffer')
        self.port = self.get_parameter_value('port')
        self.only_allow_own_IP = self.get_parameter_value('only_allow_own_IP')
        self.allowed_IPs = self.get_parameter_value('allowed_IPs')
        self._proto = protocoll()
        self.cams = CamDevices()
        self.ClientThreads = []
        self.service = ThreadedServer(self._proto,self.logger, self.port, self.video_buffer, self.PATH_CERT, self.PATH_PRIVKEY,self.cams,self.ClientThreads, self.proxyUrl,self.proxy_credentials,self.proxy_auth_type, self.only_allow_own_IP,self.sh,self.allowed_IPs)
        self.service.name = 'AlexaCamProxy4P3-Handler'
        self.TestSocket = None

        
        # Status No. Todo
        # done    0. - make Threads stable
        # done    1. - Build a Class-Structure for Camera´s with traffic, last used, last client, active client
        # done    2. - Get all Camera-Devices - done by parse-item
        # done    3. - Parse Proxy-Url to real and back (Class Structur)
        # done    4. - Build Thread-Modell with Callback for Traffic and so on
        # done    5. - Give all the statistics to the WebInterface (not really a Problem)
        # done    6. - Inject real-Url in Client Request -> Hopefully it works
        # open    7. - prettify Thread-Details in WebInterface
        # done    8. - Secure Access by allowing only own public IP-Adress
        # open    9. - Secure Access by User:PWD
    
        # get the parameters for the plugin (as defined in metadata plugin.yaml):
        #   self.param1 = self.get_parameter_value('param1')

        # Initialization code goes here

        # On initialization error use:
        #   self._init_complete = False
        #   return

        if not self.init_webinterface():
            self._init_complete = False

        return


        
    def run(self):
        self.CreateTestSocket()
        self.logger.info("Plugin '{}': start method called".format(self.get_fullname()))
        self._proto.addEntry('INFO    ',"Plugin '{}': start method called".format(self.get_fullname()))
        try:
            myFile = open(self.PATH_CERT,"r")
            myFile.close()
        except Exception as err:
            self._proto.addEntry('ERROR   ',"Access Error to Cert-File {} - Error {}".format(self.PATH_CERT, err))
            self.logger.error("Access Error to Cert-File {} - Error {}".format(self.PATH_CERT,err))
            self.alive= False
            exit(1)
        try:
            myFile = open(self.PATH_PRIVKEY,"r")
            myFile.close()
        except:
            self.logger.error("Access Error to Cert-Key-File {0}".format(self.PATH_PRIVKEY),' Error : ',err)
            self._proto.addEntry('ERROR   ',"Access Error to Cert-File {0} - Error {}".format(self.PATH_CERT, err))
            self.alive= False
            exit(1)

        self.service.start()


        self.alive = True
        '''
        while self.alive:
            pass

            if len(self.ClientThreads ) > 0:
                for t in self.ClientThreads:
                    if t.alive == False: 
                        self.CloseSockets(t)
                        try:            # Save Values
                            t.actCam.proxied_bytes +=t.proxied_bytes
                            self.logger.debug("ProxyCam4AlexaP3: saved proxied Bytes")
                        except Exception as err:
                            self.logger.debug("ProxyCam4AlexaP3: problem while saving proxied Bytes")
                        try:
                            Threadname = t.name
                            self.ClientThreads.remove(t)
                        except:
                            pass
                        
                        self.logger.debug("ProxyCam4AlexaP3: stopped Thread : %s " % Threadname)

            time.sleep(2)
        '''
        

    def stop(self):
        self.logger.info("Plugin '{}': stop method called".format(self.get_fullname()))
        self.TestSocket.stop()
        self.service.stop()
        try:
            self.service.sock.shutdown(socket.SHUT_RDWR)
            self.service.sock.close()
        except Exception as err:
            self.logger.info("Plugin '{}': Error while trying to close socket from Father-Thread : {}".format(self.get_fullname(),err))
            print ("Error while trying to close socket from Father-Thread",err)
            pass
        
        
        self.alive = False
    
    def CreateTestSocket(self):
        self.TestSocket = TestSocket(self._proto, self.port, self.logger,self.video_buffer,self.sh)
        self.TestSocket.name = 'AlexaCamProxy4P3-Testsocket'
        self.TestSocket.start()
    
    def CloseSockets(self,thread):
        try:
            thread.mysocks.remove(thread.client)
            thread.mysocks.remove(thread.server)
        except:
            self.logger.debug("ProxyCam4AlexaP3: could not remove mysocks")
        try:
            thread.client.shutdown(socket.SHUT_RDWR)
            thread.client.close()
            self.logger.debug("ProxyCam4AlexaP3: Client socket closed")
        except Exception as errr:
            self.logger.debug("ProxyCam4AlexaP3: Client socket already close")
        try:
            thread.server.shutdown(socket.SHUT_RDWR)
            thread.server.close()
            self.logger.debug("ProxyCam4AlexaP3: Server socket closed")
        except Exception as errr:
            self.logger.debug("ProxyCam4AlexaP3: Server socket already close")

  

    def parse_item(self, item):
        """
        Default plugin parse_item method. Is called when the plugin is initialized.
        The plugin can, corresponding to its attribute keywords, decide what to do with
        the item in future, like adding it to an internal array for future reference
        :param item:    The item to process.
        :return:        If the plugin needs to be informed of an items change you should return a call back function
                        like the function update_item down below. An example when this is needed is the knx plugin
                        where parse_item returns the update_item function when the attribute knx_send is found.
                        This means that when the items value is about to be updated, the call back function is called
                        with the item, caller, source and dest as arguments and in case of the knx plugin the value
                        can be sent to the knx with a knx write function within the knx plugin.
        
        if self.has_iattr(item.conf, 'foo_itemtag'):
            self.logger.debug("Plugin '{}': parse item: {}".format(self.get_fullname(), item))
        """

           
        # add the needed Information to the Items, its hard to modify Items, but neccessary
        # add a attribute for each Stream if Proxy is defined
        # add a Camera for our own use for proxying it
        if 'alexa_csc_proxy_uri' in item.conf:
            # walk over all defined Streams
            i=1
            while i <= 3:
                myStream='alexa_proxy_url-{}'.format(i)
                if myStream in item.conf:
                    try:

                        cam_id = item.conf[myStream]
                        
                       
                        if not self.cams.exists(cam_id):
                            try:
                                self.cams.put( Cam(cam_id) )
                            except Exception as err:
                                print("Error:" ,err)
                        
                        cam = self.cams.get(cam_id)
                        # Now add the real URL to our Cam
                        
                        camera_uri = item.conf['alexa_csc_uri']
                        camera_uri = json.loads(camera_uri)
                        
                        try:
                            cam.real_Url=camera_uri['Stream{}'.format(i)]
                            myProxiedurl=item.conf['alexa_proxy_url-{}'.format(i)]
                            cam.proxied_Url = myProxiedurl
                        except Exception as err:
                            print(err)
                        
                        if 'alexa_description' in item.conf:
                            cam.name = item.conf['alexa_description']
                        
                        if not('alexa_description' in item.conf):
                            cam.name = item.conf['alexa_device']
                        
                        if 'alexa_proxy_credentials' in item.conf:
                            cam.proxy_credentials = item.conf['alexa_proxy_credentials']
                        
                        if 'alexa_cam_modifiers' in item.conf:
                            cam.alexa_cam_modifiers = item.conf['alexa_cam_modifiers']
                            
                        myStream='alexa_stream_{}'.format(i)
                        authorization = item.conf[myStream]
                        authorization = json.loads(authorization)
                        
                        try:
                            for auth in authorization['authorizationTypes']:
                                cam.authorization.append(auth)    
                        except Exception as err:
                            pass
                            
                        if 'alexa_auth_cred' in item.conf:
                            credentials = item.conf['alexa_auth_cred'].split(':')
                            cam.user = credentials[0]
                            cam.pwd = credentials[1]

                        self.logger.debug("CamProxy4AlexaP3: {}-added Camera-Streams = {}".format(item.id(), cam.real_Url))
                    except Exception as err:
                        self.logger.debug("CamProxy4AlexaP3: {}-wrong Stream Settings = {}".format(item.id(), err))
                i +=1
        
        return None
            
            
    def parse_logic(self, logic):
        
        if 'xxx' in logic.conf:
            # self.function(logic['name'])
            pass

    def update_item(self, item, caller=None, source=None, dest=None):

        if item():
            if self.has_iattr(item.conf, 'foo_itemtag'):
                self.logger.debug(
                    "Plugin '{}': update_item ws called with item '{}' from caller '{}', source '{}' and dest '{}'".format(
                        self.get_fullname(), item, caller, source, dest))
            pass



    def init_webinterface(self):
        """"
        Initialize the web interface for this plugin

        This method is only needed if the plugin is implementing a web interface
        """
        try:
            self.mod_http = Modules.get_instance().get_module(
                'http')  # try/except to handle running in a core version that does not support modules
        except:
            self.mod_http = None
        if self.mod_http == None:
            self.logger.error("Plugin '{}': Not initializing the web interface".format(self.get_shortname()))
            return False

        # set application configuration for cherrypy
        webif_dir = self.path_join(self.get_plugin_dir(), 'webif')
        config = {
            '/': {
                'tools.staticdir.root': webif_dir,
            },
            '/static': {
                'tools.staticdir.on': True,
                'tools.staticdir.dir': 'static'
            }
        }

        # Register the web interface as a cherrypy app
        self.mod_http.register_webif(WebInterface(webif_dir, self),
                                     self.get_shortname(),
                                     config,
                                     self.get_classname(), self.get_instance_name(),
                                     description='')

        return True


# ------------------------------------------
#    Webinterface of the plugin
# ------------------------------------------

import cherrypy
from jinja2 import Environment, FileSystemLoader

class WebInterface(SmartPluginWebIf):


    def __init__(self, webif_dir, plugin):
        """
        Initialization of instance of class WebInterface

        :param webif_dir: directory where the webinterface of the plugin resides
        :param plugin: instance of the plugin
        :type webif_dir: str
        :type plugin: object
        """
        self.logger = logging.getLogger(__name__)
        self.webif_dir = webif_dir
        self.plugin = plugin
        self.tplenv = self.init_template_environment()
        self.items = Items.get_instance()
    
    @cherrypy.expose
    def store_credentials_html(self, encoded='', pwd = '', user= '', store_2_config=None):
        txt_Result = []
        myCredentials = user+':'+pwd
        byte_credentials = base64.b64encode(myCredentials.encode('utf-8'))
        encoded = byte_credentials.decode("utf-8")
        txt_Result.append("encoded:"+encoded) 
        txt_Result.append("Encoding done")
        conf_file=self.plugin.sh.get_basedir()+'/etc/plugin.yaml'
        if (store_2_config == 'true'):
            new_conf = ""
            with open (conf_file, 'r') as myFile:
                for line in myFile:
                    if line.find('proxy_credentials') > 0:
                        line = '    proxy_credentials: '+encoded+ "\r\n"
                    new_conf += line 
            myFile.close()         
            txt_Result.append("replaced credentials in temporary file")
            with open (conf_file, 'w') as myFile:
                for line in new_conf.splitlines():
                    myFile.write(line+'\r\n')
            myFile.close()
            txt_Result.append("stored new config to filesystem")
            txt_Result.append("Please reload page to refresh Links for Testsockets")
        return json.dumps(txt_Result)
    
    @cherrypy.expose
    def commit_html(self, VideoBuffer='', authorization_1= ''):
        txt_Result = []
        conf_file=self.plugin.sh.get_basedir()+'/etc/plugin.yaml'
        new_conf = ""
        with open (conf_file, 'r') as myFile:
            for line in myFile:
                if line.find('video_buffer') > 0:
                    line = '    video_buffer: '+VideoBuffer+ "\r\n"
                if line.find('proxy_auth_type') > 0:
                    line = '    proxy_auth_type: '+authorization_1+ "\r\n"
                new_conf += line 
        myFile.close()         
        txt_Result.append("replaced credentials in temporary file")
        with open (conf_file, 'w') as myFile:
            for line in new_conf.splitlines():
                myFile.write(line+'\r\n')
        myFile.close()
        txt_Result.append("stored new config to filesystem")
        self.plugin.service.proxy_auth_type = authorization_1
        self.plugin.proxy_auth_type =authorization_1
        
        self.plugin.service.BUFF_SIZE_SERVER = VideoBuffer
        self.plugin.video_buffer = VideoBuffer
        return json.dumps(txt_Result)

    @cherrypy.expose
    def thread_list_json_html(self):
        """
        returns a list of Threads as json structure
        """
        sa_Skull = '<i style=color:black;" class="fas fa-skull-crossbones"></i>'
        sa_Running = '<i style=color:green;" class="fas fa-play-circle"></i>'
        thread_data = []
        for t in self.plugin.service.ClientThreads:
            if t.alive == True:
                try:
                    thread_dict = {
                                    'Thread' : t.name,
                                    'real_URL' : t.actCam.real_Url,
                                    'Status' : sa_Running
                                  }
                    thread_data.append(thread_dict)
                except Exception as err:
                    self.logger.error('Error while build Threadlist for WebInterface : {}'.format(err))
            else:
                try:
                    thread_dict = {
                                    'Thread' : t.name,
                                    'real_URL' : t.actCam.real_Url,
                                    'Status' : sa_Skull
                                  }
                    thread_data.append(thread_dict)
                except Exception as err:
                    self.logger.error('Error while build Threadlist for WebInterface : {}'.format(err))
        if len(thread_data) ==0:
            thread_dict = {
                            'Thread' : 'No Active Thread',
                            'real_URL' : ''
                          }
            thread_data.append(thread_dict)
        return json.dumps(thread_data)
    
    
    @cherrypy.expose
    def get_proto_html(self, proto_Name= None):
        if proto_Name == 'proto_states_check':
            return json.dumps(self.plugin._proto.log)
    
    
    @cherrypy.expose
    def clear_proto_html(self, proto_Name= None):
        if proto_Name == 'btn_clear_proto_states':
            self.plugin._proto.log = []
            return None
    
    @cherrypy.expose
    def toggle_TestSocket_html(self, enabled= None):
        if enabled == 'true':
            try:
                self.plugin.CreateTestSocket()
                
            except:
                pass
        else:
            try:
                self.plugin.TestSocket.stop()
                self.plugin.TestSocket = None
            except:
                pass
        
    
    @cherrypy.expose
    def thread_details_json_html(self, thread_name):
        """
        returns a detailed Informations for a camera-Thread
        """
        info_data = []
        if thread_name != 'No Active Thread' or thread_name == '': 
            for t in self.plugin.service.ClientThreads:
                if t.name != thread_name:
                    # not this Thread selected
                    continue
                else:
                    # found correct Thread
                    try:
                        actDateTime = datetime.now()
                        duration_sec = mktime(actDateTime.timetuple()) - mktime(t.last_Session_Start.timetuple())
                        Session_duration = str(timedelta(seconds=duration_sec))
                        info_data = {
                            'Name' : t.name,
                            'Video-Buffer-Size': t.BUFF_SIZE_SERVER,
                            'proxied_bytes' : t.proxied_bytes,
                            'last_Session_Start' : t.last_Session_Start.strftime("%Y-%m-%d %H:%M:%S"),
                            #'last_Session_End' : t.last_Session_End.strftime("%Y-%m-%d %H:%M:%S"),
                            'Session_duration' : Session_duration,
                            'server_url' : t.server_url,
                            'peer' : t.peer,
                            'Proxy-Credentials' : t.proxy_credentials,
                            
                            
                            #Cam - Infos
                            'Cam-Authorization' : str(t.actCam.authorization),
                            'Cam-ID' : t.actCam.id,
                            'Cam-proxied_Url' : t.actCam.proxied_Url,
                            'Cam-real_Url' : t.actCam.real_Url,
                            'Cam-User' : t.actCam.user,
                            'Cam-Password' : t.actCam.pwd
                            }
                        break
                    except Exception as err:
                        print("Error from Service :",err )
                        info_data = {
                                    'Error occured' : 'please try again'
                                    }
        else:
            info_data = {
                        'No Active Thread' : 'select a Thread on the left side'
                        }
            
        return json.dumps(info_data)
    
    
    @cherrypy.expose
    def index(self, reload=None):
        """
        Build index.html for cherrypy

        Render the template and return the html file to be delivered to the browser

        :return: contents of the template after beeing rendered
        """
        # Collect Cams without Proxy
        cam_tls_items = []
        # Collext all Cams
        for item in self.items.return_items():
            #if (self.plugin.has_iattr(item.conf, 'alexa_csc_proxy_uri')):
            #    cam_proxied_items.append(item)
            if ((self.plugin.has_iattr(item.conf, 'alexa_csc_uri')) and not (self.plugin.has_iattr(item.conf, 'alexa_csc_proxy_uri'))):
                cam_tls_items.append(item)
        
        # Internal-LogFile
        try:
            my_state_loglines = self.plugin._proto.log
            state_log_file = ''
            for line in my_state_loglines:
                state_log_file += str(line)+'\n'
        except:
            state_log_file = 'No Data available right now\n'
        
        # Get own IP-Adress
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            myIP = (s.getsockname()[0])
            s.close()
        except:
            myIP = ""
            
        # Collect proxied Cams
        cam_proxied_items = []
        _link = '<a href="rtsp://{}{}:5001/{}">{}</font></a>'
        myCams = self.plugin.cams.Cams
        for actCam in myCams:
            newEntry=dict()
            Cam2Add=self.plugin.cams.Cams.get(actCam)
            _href = Cam2Add.proxied_Url.split("/")[-1]
            if self.plugin.service.proxy_credentials != "" and self.plugin.service.proxy_auth_type != "NONE" :
                _Credentials = self.plugin.service.proxy_credentials+'@'
            else:
                _Credentials = ""
            newEntry['name'] = Cam2Add.name
            newEntry['real_Url'] = Cam2Add.real_Url
            newEntry['proxied_Url'] = (_link.format(_Credentials,myIP,_href ,Cam2Add.proxied_Url))
            newEntry['proxied_mb_Session'] = "%.1f" % 0.00
            newEntry['proxied_mb_total'] = "%.1f" % (Cam2Add.proxied_bytes / 1024.0 / 1024.0)
            newEntry['Sessions_total'] = Cam2Add.Sessions_total
            newEntry['last_Session_duration'] = Cam2Add.last_Session_duration
            newEntry['alexa_cam_modifiers'] = Cam2Add.alexa_cam_modifiers
            
            if Cam2Add.last_Session != None:
                newEntry['last_Session'] = str(Cam2Add.last_Session.strftime('Date: %a, %d %b %H:%M:%S %Z %Y'))
            else:
                newEntry['last_Session'] = 'never asked for'
            
            cam_proxied_items.append(newEntry)
        
        try:        
            myService = self.plugin.service
            myThreadCount=len(myService.ClientThreads)
            # SSL-Infos
            try:
                my_Ciphers = myService.cert_ciphers
                my_Ciphers = my_Ciphers.replace(":","<br>")
                my_Cert_Dict = myService.cert_dict
                if my_Cert_Dict != '':
                    cert_subject = dict(x[0] for x in my_Cert_Dict['subject'])
                    cert_issued_to = cert_subject['commonName']
                    cert_subject = dict(x[0] for x in my_Cert_Dict['issuer'])
                    cert_issued_by = cert_subject['commonName']
                    cert_notafter = my_Cert_Dict['notAfter']
                    cert_notBefore = my_Cert_Dict['notBefore']
            except Exception as err:
                print("Error from Service :",err )
                
        except Exception as err:
            print("Error from Service :",err )
        
        # Show the public IP
        try:
            if (self.plugin.only_allow_own_IP):
                myPublicIP = self.plugin.service.myIP
                if (self.plugin.only_allow_own_IP):
                    SubNetTest = self.plugin.service.myLan.split(".")
                    myLan = self.plugin.service.myLan
                    SubNetTest = len(SubNetTest)
                    for i in range(SubNetTest-2,2):
                        myLan += '.*'
                    myPublicIP += ' / 127.0.0.1 / '+myLan+'/'+self.plugin.allowed_IPs
            else:
                myPublicIP = '*'
        except Exception as err:
            print("Error while looking for public IP :",err )
        try:
            myCredentials=self.plugin.service.proxy_credentials
        except Exception as err:
            myCredentials=''
            print("Error while building up Proxy-Credentials :",err )
        try:
            proxy_auth_type = self.plugin.service.proxy_auth_type
        except:
            proxy_auth_type='not found'
            print("Error while building up Proxy-Credentials :",err )
        
        try:
            if self.plugin.TestSocket.alive:
                testsocket_active = "checked"
            else:
                testsocket_active = ""                
        except:
            testsocket_active = ""
        tmpl = self.tplenv.get_template('index.html')
        return tmpl.render(plugin_shortname=self.plugin.get_shortname(), plugin_version=self.plugin.get_version(),
                           plugin_info=self.plugin.get_info(), p=self.plugin,
                           proxied_Cams=str(len(cam_proxied_items)) ,
                           standard_Cams=str(len(cam_tls_items)),
                           publicIP=str(myPublicIP),
                           proxy_auth_type=str(proxy_auth_type),
                           proxyCredentials=str(myCredentials),
                           items_proxied=sorted(cam_proxied_items, key=lambda k: str.lower(k['name'])),
                           item_tls=sorted(cam_tls_items, key=lambda k: str.lower(k['_path'])),
                           cert_issued_by=cert_issued_by, cert_issued_to=cert_issued_to ,
                           cert_notafter=cert_notafter ,cert_notBefore=cert_notBefore,my_Ciphers=my_Ciphers,
                           video_buffer = self.plugin.video_buffer,
                           state_log_lines=state_log_file,
                           testsocket_active = testsocket_active
                           )
        
                                   
