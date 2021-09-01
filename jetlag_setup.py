from gui_fun import gui_fun, settings
from jetlag import JetLag, Auth

class Loader:
    def __init__(self):
        self.auth = None
        self.jlag = None
        settings(self.loadf,{"password":"password","utype":["tapis","agave"]})
        self.r=gui_fun(self.loadf)
        self.r.add_listener(self.on_load)

    def loadf(self, utype, user=None, password=None, baseurl=None, tenant=None):
        self.auth = Auth(utype, user, password, baseurl, tenant)
        self.auth.create_or_refresh_token()
        self.jlag = JetLag(self.auth)

    def query_jetlag_id(self, jid):
        return jid

    def set_jetlag_id(self, jid):
        self.jlag = JetLag(self.auth, jetlag_id=jid)
        print("jetlag id set to:",jid)

    def on_load(self, _):
        jids = self.jlag.jetlag_ids()
        settings(self.query_jetlag_id,{"jid":jids})
        if len(jids)==0:
            print("You are not authorized to use JetLag. Contact sbrandt@cct.lsu.edu")
        else:
            res = gui_fun(self.query_jetlag_id)
            res.add_listener(self.set_jetlag_id)

