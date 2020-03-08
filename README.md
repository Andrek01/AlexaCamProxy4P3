# AlexaCamProxy - Version 1.0.0
# Multi-Threading Camera-Proxy for Alexa4P3-Plugin


## Table of Content
1. [How it works](#howitworks)
2. [ChangeLog](#ChangeLog) <sup><span style="color:red"> **Neu**</sup>
3. [Plugin - Configuration](#config) <sup><span style="color:red"> **Neu**</sup>
4. [Network - Configuration](#network) <sup><span style="color:red"> **Neu**</sup>
	- [Setup A](#SetupA) - household typical network and infrastructure using existing certificate 
	- [Setup B](#SetupB) - household typical network and infrastructure using new Domain and certificate (still searching for supporting DnyDNS-Provider)
	- [Setup C](#SetupC) - Setup with a official Domain or a DynDNS-Domain which allows you to create Sub-Domains and a working NameServer in your LAN
5. [Web Interface](#webinterface) <sup><span style="color:red"> **Neu**</sup>
6. [Testsocket](#testsocket) <sup><span style="color:red"> **Neu**</sup>
7. [Communication scheme](#scheme) <sup><span style="color:red"> **Neu**</sup>
8. [Known issues](#issues) <sup><span style="color:red"> **Neu**</sup>


## What the Plugin do :

The Plugin provides private Cameras in the local network for Amazon devices like Echo Show / Echo Spot / FireTV. The reqirements of Amazon for cameras are :

- encrypted Connection via TLSv1.2
- use an officiel certificate (not self signed)
- using Port 443

So it´s not possible to use private cameras (on local networks) without any cheats,
this plugin will fix this problem

<a name="howitworks"/></a>
## How it works: 

The plugin provides a socket on Port 443 and listens to incoming connections. If there is a request to a proxied camera the plugin injects the real URL of the stream in the request, creates a second socket and connects to the camera.
If "only_allow_own_IP" is set to true only Connections from the own IP-Adress, Local-Host and from the Local network will be accepted.
The Local-Host Access is needed for the Testsocket.
All connection-tries from other hosts will be refused at once.

<strong>The Option "only_allow_own_IP" will only work in non routed networks. If you have a routed network it should not be neccessary to protect the AlexaCamProxy with this option cause you can handle it before.</strong>

<a name="ChangeLog"/></a>
## Change-Log

#### 2020.03.04 - Version 1.0.0

- added access from own network when "only_allow_own_IP" is set to "true"
- added "Breakline for unbreakable Lines" in Streams (needed for some Cams to get it work)
- added parameters from item-definition for "/del_audio" - this remove the Audio-Stream from SDP-Setup (needed for some Alexa-Devices and some Cam's)

#### 2020.02.25 - Version 1.0.0

- added Testsocket in WebInterface with link to rtsp-URL for VLC-Player

#### 2018.03.03 - Version 1.0.0

- added Support for Basic/Digest Authentication to the CamProxy
- added Access only for restricted / own public IP (new Parameter in plugin.yaml "only_allow_own_IP")

#### 2018.01.26 - launch of Version 1.0.0

- Beta Version for tests distributed



## Requirements

Nothing special needed, see Needed software

### Needed software

* running Plugin Alexa4P3
* SmartHomeNG >= 1.5.1
* Python >= 3.0
* for the WebInteface you need the http-module of SmartHomeNG
* SmartHomeSkill with Payload V3 in Amazon Developer Console
* working Lambda function in Amazon AWS
* running Nginx with guilty certificate (official not self signed)
* public URL via DYNDNS-Service
* reachable Port 443 (you have to move NGINX to another Port) or you have configure a alternative network setup.
* Portforwarding on your router for Port 443 to your SmartHomeNG machine


## <span style="color:red">**!! Needed Access for the AlexaCamProxy on Port 443 !!**</span>

<span style="color:red">**You have to give the Plugin access to Port 443. To do this you have to give Python permissions to bind privileged ports without root access.To setup this run the following command.It´s not allowed to Bind Symlinks. So after a update of the used Python version you have to do this again.(Python3 -> Symlink to python 3.5 after Update Python3 -> Symlink to python 3.6)**</span>

## <span style="color:red">**=================================================**</span>
<pre><code>sudo setcap CAP_NET_BIND_SERVICE=+eip /usr/bin/python3.5
</code></pre>
## <span style="color:red">**=================================================**</span>


## Supported Hardware

* all Cameras with RTSP-Protocoll and Handling OPTIONS/DESCRIBE/PLAY/TEARDOWN
* only resolutions with 1080p or less will be supported by the Alexa-Devices, depending on the device you would like to use.

<a name="config"/></a>
## Plugin-Configuration

## plugin.yaml

The plugin has the following paramters in the plugin.yaml

```yaml
AlexaCamProxy4P3:
    class_name: AlexaCamProxy4P3
    class_path: plugins.alexacamproxy4p3
    port: 443
    video_buffer: 524280
    cert_path: '/usr/local/smarthome/plugins/alexacamproxy4p3/fullchain.pem'
    cert_path_key: '/usr/local/smarthome/plugins/alexacamproxy4p3/privkey.pem'
    proxy_url: '<your.domain.net>'
    proxy_credentials: '<user>:<pwd>'
    proxy_auth_type: 'DIGEST'
    only_allow_own_IP: true
```

<strong>Please do not use "proxy" in your proxy_credentials. On Test-Sockets the VLC-Player will get in trouble with it, because there is a special handling for "proxy" in VLC-Player</strong>

cert_path : File with your fullchain.pem for the URL where you want to reach your  proxied cameras

cert_path_key : File with your privkey.pem for the URL.

video_buffer : Size for the Videobuffer for streaming. Standard is 524280 bytes. My experience was :
- too small buffer, you have to wait a long time till the stream starts
- too big buffer, the streams sometimes wait for the data

Please try out what value fits to your setup and Cam´s.

proxy_url : Your Domain where the AlexaCamProxy4P3 is reachable

proxy_credentials: User:Password, this are the settings for the CamProxy himself, you can define it as wish

proxy_auth_type : Authentification-Type for the Proxy allowed values "DIGEST", "BASIC" and "NONE".

only_allow_own_IP: If set to True the CameraProxy will only allow access from your own public IP, no other Client will get Access. If set to False also foreign IP-addresses will be accepted.



<a name="network"/></a>
## Network-Configuration

What is needed ?
Tue to the fact the Amazon-Devices only connects to a secure SSL-Cam you need an URL with a guilty, not self signed certificate.
To get it work there are several solutions for this issue.

<a name="SetupA"/></a>
### A.) Easiest setup for a common household network with a DynDNS-Domain and existing Lets`Encrypt-Certificate for the NGINX

When you are using the Alexa4P3-Plugin you already have a Domain with Let's Encrypt Certificate. You can use this Certificate also for the Cam-Proxy.
<strong>Its not possible to run the AlexaCamProxy4P3 behind a NGINX and using the NGINX as reverse Proxy, the NGINX is not supporting Streams</strong>

So first copy your Certificat to the plugin folder.
Normally you will find the Certificate in :
```
/etc/letsencrypt/archive/<YOUR-DOMAIN-NAME.NET>/
```
You need the files :

privkey<strong>X</strong>.pem
fullchain<strong>X</strong>.pem

<strong>Everytime when you renew you certifcate the number of the certificate will be increased</strong>

In the folder
```
/etc/letsencrypt/live/<YOUR-DOMAIN-NAME.NET>/
```
You will find a SymLink to the actual files. You can make a copy of this files
or you have to take care using the actual files.

```
sudo cp /etc/letsencrypt/live/<YOUR-DOMAIN-NAME.NET>/fullchain.pem /usr/local/smarthome/plugins/alexacamproxy4p3/
sudo cp /etc/letsencrypt/live/<YOUR-DOMAIN-NAME.NET>/privkey.pem /usr/local/smarthome/plugins/alexacamproxy4p3/
```
give read access rights to the files for all Users or change the owner of the files depending on you own setup.
```
sudo chmod 444 /usr/local/smarthome/plugins/alexacamproxy4p3/fullchain.pem
sudo chmod 444 /usr/local/smarthome/plugins/alexacamproxy4p3/privkey.pem
```


When you have done the copy of the certificates you have to setup your router to Forward Port 443 to you smarthomeNG machine.

<strong>Please take care that your NGINX is listening on a different port. You can find this settings in your server section of the NGNIX config file - search for "listen". The config for the Image of OnkelAndy is located in /etc/nginx/conf.d/https/.conf
For other installations you should know where your Config is located or you have to search for it

#### When you change your NGINX-Config don`t forget to restart you NGINX and change the port forwarding on your router</strong>

That`s it.

<a name="SetupB"/></a>
### B.) Setup for a common household network with a DynDNS-Domain and seperate Domain for the CamProxies Lets`Encrypt-Certificate

### still searching for supporting DnyDNS-Provider, this will not work with all DynDns-Providers

If you have a DynDNS-Account which allows you to define more than one DynDNS or you would like to setup a new DynDNS-Account you can do the configuration as follows.

Create your new Domain at your DynDNS-Provider - this new Domain should point to your Router - later on you have to change it.
Now login in on your computer with installed Certbot.
Get a Certificate for your new Domain.
```
sudo certbot certonly --rsa-key-size 4096 --webroot -w /var/www/letsencrypt -d <yourdomain>.<myds>.<me>
```

<strong>Take care that the port for getting a new certificate are forwarded on you router ! Port 80 is needed to verify the IP.
</strong>

After you got your certificate you have to move it to the plugin folder (see section A)

Now you can change the IP of you new DynDNS-Domain to the IP of your smarthomeNG-machine which is running the AlexaCamProxy.

For example :
```
192.168.178.10
```

After changing the IP you can test the communication with a simple "ping" to your new domain. You should get a ping-answer from your local host.

### <strong>advantage :</strong>

For this solution its not neccessary to move the NGINX from Port 443.
No additional portforwarding is needed on your router.
You can be sure your AlexaCamProxy will only be reachable inside your local network.

### <strong>disadvantage :</strong>
Everytime you have to renew the certificate you have to change the IP at your DynDNS-Provider, after getting the certificate you have to change it back.

That`s it

<a name="SetupC"/></a>
### C. ) Setup with a official Domain or a DynDNS-Domain which allows you to create Sub-Domains and a working NameServer in your LAN

You have to create a Sub-Domain.
Create a certificate for the Sub-Domain.
Copy the certifcate to the plugin folder (see section A)
You have to add the entries in your NameServer-config to point the new Sub-Domain to your smarthomeNG-machine.

### <strong>advantage :</strong>
For this solution its not neccessary to move the NGINX from Port 443.
No additional portforwarding is needed on your router.
You can be sure your AlexaCamProxy will only be reachable inside your local network.
You dont have to make any changes on IP`s, DynDNS-Accounts or something else

### <strong>disadvantage :</strong>
None

That`s it

## items.yaml

No items or attributes have to be defined. On Startup the Plugin generates the needed attributes based on the attributes of the Alexpa4P3-Plugin.

In my point of view, no further description is needed

<a name="webinterface"/></a>
## Web-Interface: 

The Plugin has a Web-Interface.
You can see the number auf provided Camś , the allowed IP's, the configured Auhtorization-Type and the Credentials for the Proxy himself.
You can Switch ON/OFF the Testsocket.

On the fist tab you can see the Cam's that are provided, some statistics for each cam and the last request for each cam. You can change your settings, user and password for the authentication at the AlexaCamProxy. It's possible to write the changes directly to the plugin.yaml file.
Each entry for a proxied Cam will have a Link to the Testsocket.

On the second page a communication log is show, you can. It's a small self rotating log that will be only stored in the actual instance of the plugin. After restarting smarthomeNG it will be empty. You can delete the protocoll manually.

On the third page you can see the active Threads and some Details of the running Threads. The last Thread will be shown as "Dead". The Thread was already ended but still shown on this page.The last dead Threads will be cleaned up each time a new Thread is started or the plugin will be onloaded.

On the fourth page you can see some details about you certificate and the supported ciphers. The experiation date of the certificate will be interesting for most of the users.

<a name="testsocket"/></a>
## Testsocket :
When the Testsocket is enabled (see Web-Interface) you can try to connect to your Cam's via the AlexaCamProxy4P3 using VLC-Player or any other Player. The Testsocket provides a Non-SSL  listening on <strong>Port5001</strong>
The shown unique URL's for the Cameras on Tab one have a link to the Testsocket.
When asking for a Cam on the Testsocket it will connect via SSL to the real Socket and the connection will be the same as an Alexa-Device asks for.
You can test the work of the AlexaCamProxy4P3-Plugin with the Testsocket.
The human readable communication will be displayed in the communication log.

<a name="scheme"/></a>
## Communication scheme

![](./assets/CameraProxyScheme.jpg)

<a name="issues"/></a>
## Known issues

We got the experience that not all Alexa-Devices can handle all the Cam's in the same way. For example an Reolink Camera will work an Echo Show 8 with Audio on FireTv it only works without Audio.

We also got the experience that our girl-friend Alexa is a little bitchy with Audio-Streams so in case you get in trouble use the "/del_Audio" Option in the Item-settings for your Cam-Stream. (see Alexa4P3 documentation)
This option will remove the Audio-Stream in the SDP-Setup.

