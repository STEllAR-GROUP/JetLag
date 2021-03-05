from gui_fun import gui_fun, settings
from jetlag import JetLag, Auth

class Loader:
    def __init__(self):
        self.auth = None
        self.jlag = None
    def loadf(self, utype, user=None, password=None, baseurl=None, tenant=None):
        self.auth = Auth(utype, user, password, baseurl, tenant)
        self.jlag = JetLag(self.auth)

loader = Loader()

settings(loader.loadf,{"password":"password","utype":["tapis","agave"]})
r=gui_fun(loader.loadf)
uv = None

def query_jetlag_id(jid):
    return jid


def set_jetlag_id(jid):
    global uv
    loader.jlag = JetLag(loader.auth, jetlag_id=jid)
    print("jetlag id set to:",jid)
    uv = loader.jlag


def on_load(_):
    jids = loader.jlag.jetlag_ids()
    if len(jids)==0:
        print("You are not authorized to use JetLag. Contact sbrandt@cct.lsu.edu")
    else:
        settings(query_jetlag_id,{"jid":jids})
        res = gui_fun(query_jetlag_id)
        res.add_listener(set_jetlag_id)


r.add_listener(on_load)
