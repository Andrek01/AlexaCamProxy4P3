class CamDevices(object):
    def __init__(self):
        self.Cams = {}

    def exists(self, id):
        return id in self.Cams

    def get(self, id):
        return self.Cams[id]

    def put(self, cam):
        self.Cams[cam.id] = cam

    def all(self):
        return list( self.Cam.values() )

    def getCambyUUID(self, url):
        for myCam in self.Cams:
            if url in self.Cams[myCam].proxied_Url:
                return self.Cams[myCam]
        return None
    
class Cam(object):
    def __init__(self, id):
        self.id = id
        self.name = ''
        self.proxied_Url = ''
        self.real_Url = ''
        self.user = ''
        self.pwd = ''
        self.proxied_bytes = 0
        self.proxied_mb = 0.0
        self.last_Session = None
        self.last_Session_Start = None
        self.last_Session_End = None
        self.last_Session_duration = ''
        self.Sessions_total = 0
        self.proxy_credentials= ''
        self.authorization = []
    


