from typing import cast, List, Optional
from jetlag2 import AuthBase, home, pcmd, JDict, Machine, machine_from_data, JetlagBase
from colored import colored
import os, json
import uuid

class SSHAuth(AuthBase):
    def __init__(self)->None:
        AuthBase.__init__(self)
        os.makedirs(self.get_auth_dir(), exist_ok=True)
        self.priv_key = os.path.join(self.get_auth_dir(), "id_rsa")
        self.pub_key = self.priv_key + ".pub"
        if not os.path.exists(self.priv_key):
            r, o, e = pcmd(["ssh-keygen","-m","PEM","-t","rsa","-f",self.priv_key,"-P",""])
            print(colored(o, "green"), end="")
            print(colored(e, "red"), end="")

    def __repr__(self)->str:
        return "SSHAuth"

    def get_idstr(self)->str:
        return "ssh"

    def refresh_token(self)->bool:
        return True

    def get_auth_data(self)->JDict:
        if not os.path.exists(self.get_auth_file()):
            return {"systems":{}}
        with open(self.get_auth_file(), "r") as fd:
            s = fd.read()
            if s == "":
                return {"systems":{}}
            return cast(JDict, json.loads(s))

    def get_auth_dir(self)->str:
        return os.path.join(home, ".ssh-auth")

    def get_auth_file(self)->str:
        return os.path.join(self.get_auth_dir(), "current")
        
    def systems_list(self)->List[Machine]:
        sl : List[Machine] = []
        d = cast(JDict, self.get_auth_data()["systems"])
        for k in d:
            md = cast(JDict, d[k])
            sl += [machine_from_data(md)]
        return sl

    def get_system(self,name:str)->Optional[Machine]:
        d = cast(JDict, self.get_auth_data()["systems"])
        md = cast(JDict, d[name])
        return machine_from_data(md)

    def add_or_update_system(self,machine:Machine)->None:
        data = self.get_auth_data()
        d = cast(JDict, data["systems"])
        d[machine.name] = machine.to_data()
        with open(self.get_auth_file(), "w") as fd:
            print(json.dumps(data),file=fd)

class SSHJob(JobBase):
    def __init__(self, jetlag:'JetlagBase', jobid:str, jobname:str)->None:
        JobBase.__init__(jetlag, jobid, jobname)

class SSHJetlag(JetlagBase):
    def __init__(self, auth, machine)->None:
        JetlagBase.__init__(self, auth, machine)

    def login(self)->str:
        return f"{self.machine.user}@{self.machine.name}.{self.machine.domain}"

    def configure(self)->None:
        r = call(["ssh",self.login(),"true"])
        assert r == 0, f"configure() failed for machine {self.login()}"

    def make_dir(self, dir_name)->None:
        r = call(["ssh",self.login(),"mkdir","-p",dir_name])
        assert r == 0, f"Creation of directory '{dir_name}' failed on machine '{self.login()}"

    def get_access(self,app:str='queue')->List[str]:
        # Not relevant for SSH
        return []
    
    def set_access(self,userid:str,allow:bool)->bool:
        return True
    
    def get_job_file(self,jobid:Union[str,JobBase],remote_fname:str,local_fname:Optional[str])->bytes:
        ...
    
    def get_job_file_list(self,jobid:str,dir:str='',recurse:bool=False)->List[str]:
        ...
   
    def hello_world_job(self, jtype:str='fork')->JobBase:
        ...
    
    def create_job_id(self)->str:
        return uuid.uuid4()

    def get_work_dir(self)->str:
        if self.machine.work_dir is not None:
            return self.machine.work_dir
        return self.machine.home_dir + "/work"
        
    def run_job(self, job_name:str, script_file:str, input_tgz:tgz_type={}, jtype:str='fork',
            nodes:int=1, ppn:int=16, run_time:ostr=None, nx:int=0, ny:int=0, nz:int=0)->JobBase:
        job_id = self.create_job_id()
        remote_dir = self.machine.get_work_dir() + "/job-" + job_id
        self.make_dir(remote_dir)
        r = call(["scp",script_file,self.login()+":"+remote_dir])
        assert r != 0
        if jtype == 'fork':
            r = call(["ssh",self.login(),"/usr/bin/env","-C",remote_dir,"bash",script_file])
        else:
            raise Exception()
   
    def get_job_history(self, job_id:str)->JType:
        ...
