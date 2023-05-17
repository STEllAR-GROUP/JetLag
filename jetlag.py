from abc import ABCMeta, abstractmethod
from typing import List, Tuple, Any, Union, Dict, Optional, cast, TypedDict, Final
from ser import ser, deser
from tempfile import NamedTemporaryFile
from names import rand_name
import hashlib, base64, re, os
from random import randint
from datetime import datetime
from time import time
import json
from copy import copy, deepcopy
from time import sleep, time
from math import log, ceil
import sys
from subprocess import Popen, PIPE
from colored import colored
import pprint
from traceback import print_exc
from here import here
import tarfile
import pwd
from requests.models import Response

_here = os.path.realpath(".")

pp = pprint.PrettyPrinter(indent=2)

os.environ["AGAVE_JSON_PARSER"] = "jq"

class ClientException(Exception):
    def __init__(self, clients: List[str]):
        self.clients = clients
        Exception.__init__(self, "Valid clients: "+str(clients))

def normalize_dir(d: str)->str:
    while d.endswith("/"):
        if d == "/":
            return d
        d = d[:-1]
    return d

##################### STATUS #######################

job_done_status = ["FAILED", "FINISHED", "STOPPED", "BLOCKED"]
status_color = {
    "FAILED" : "red",
    "STOPPED" : "red",
    "BLOCKED" : "magenta",
    "QUEUED" : "yellow",
    "SUBMITTING" : "yellow",
    "RUNNING" : "green",
    "CLEANING_UP" : "green",
    "FINISHED" : "green",
    "PENDING" : "cyan",
}
def get_status_color(status: str)->str:
    if status in status_color:
        return status_color[status]
    else:
        return "yellow"

##################### JSON DATA #######################

# Captures an arbitrary JSon data structure
JType = Union[Dict[str, 'JType'], List['JType'], str, int, bool, float]
JDict = Dict[str, JType]
JList = List[JType]

def show_json(jdata: JType, indent: int = 0)->None:
    if jdata is None:
        print('none')
    elif type(jdata) == str:
        print(jdata.strip())
    elif type(jdata) in [bool, int, float]:
        print(jdata)
    elif type(jdata) == list:
        print('[')
        for i in range(len(jdata)):
            print(' ' * (indent + 2), colored(str(i), "green"), ": ", sep='', end='')
            print(jdata[i], indent + 4)
        print(' ' * indent, ']', sep='')
    elif type(jdata) == dict:
        print('{')
        for k in jdata:
            print(' ' * (indent + 2), colored(str(k), "cyan"), ": ", sep='', end='')
            show_json(jdata[k], indent + 4)
        print(' ' * indent, '}', sep='')
    else:
        raise Exception(type(jdata))

def rm_tag(d: JType, tag: str)->JType:
    """
    Recurse through arbitrary lists, dicts, etc.
    and remove the tag key from any dict.
    """
    if type(d) == dict:
        r = {}
        for k in d:
            if k == tag:
                continue
            r[k] = rm_auth(d[k])
        return r
    elif type(d) == list:
        return [rm_auth(x) for x in d]
    else:
        return d

def rm_auth(d: JType)->JType:
    return rm_tag(d, "auth")

def link_filter(data: JType)->JType:
    return rm_tag(data, "_links")

##################### VERBOSITY #######################

verbose: bool = False
def set_verbose(v: bool)->None:
    global verbose
    verbose = v
def get_verbose()->bool:
    return verbose

##################### DATE AND TIME #######################

def ago(ts: float)->str:
    s = []
    year_sec = 60*60*24*355
    if ts > year_sec:
        years = int(ts/year_sec)
        ts -= years*year_sec
        s += ["%d years" % years]
    day_sec = 60*60*24
    if ts > day_sec:
        days = int(ts/day_sec)
        ts -= days*day_sec
        s += ["%d days" % days]
    hour_sec = 60*60
    if ts > hour_sec:
        hours = int(ts/hour_sec)
        ts -= hours*hour_sec
        s += ["%d hours" % hours]
    min_sec = 60
    if ts > min_sec:
        mins = int(ts/min_sec)
        ts -= mins*min_sec
        s += ["%d mins" % mins]
    if ts != 0:
        s += ["%.1f secs" % ts]
    return " + ".join(s)

def age(fname: str)->float:
    "Compute the age of a file in seconds"
    t1 = os.path.getmtime(fname)
    t2 = time()
    return t2 - t1

##################### COMMAND UTILS #######################

def pause()->None:
    pass #sleep(5)

ostr = Optional[str]

def pcmd(cmd: List[str], input: ostr = None, cwd: ostr = None)->Tuple[int, str, str]:
    """
    Generalized pipe command with some convenient options
    """
    if verbose:
        print(colored(' '.join(cmd), "magenta"))
    p = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, universal_newlines=True, cwd=cwd)
    if input is not None:
        if verbose:
            print("send input...")
        out, err = p.communicate(input=input)
    else:
        out, err = p.communicate()
    if verbose:
        print(colored(out, "green"), end='')
    if err != '':
        if verbose:
            print(colored(err, "red"), end='')
    return p.returncode, out, err

##################### CONSTANTS #######################

# Most reliable way to get HOME
home = pwd.getpwuid(os.getuid()).pw_dir

##################### STRING UTILS #######################

def idstr(idlen: int=20)->str:
    """
    Generate a random id string
    """
    base = ''
    for i in range(ord('a'), ord('z')+1):
        base += chr(i)
    for i in range(ord('A'), ord('Z')+1):
        base += chr(i)
    for i in range(ord('0'), ord('9')+1):
        base += chr(i)
    s = ''
    for i in range(idlen):
        s += base[randint(0, len(base)-1)]
    return s

def codeme(m : Union[str,bytes]) -> str:
    """
    Convert a string or bitestring to an md5sum
    and encde it in base64.
    """
    if type(m) == str:
        b = m.encode()
    elif type(m) == bytes:
        b = m
    else:
        raise Exception(str(type(m)))
    h = hashlib.md5(b)
    v = base64.b64encode(h.digest())
    s = re.sub(r'[\+/]','_', v.decode())
    return s[:-2]

##################### UTILS #######################

FILE_LINK_SIZE : Final = 1e6

class FileLink:
    def __init__(self, link:str)->None:
        self.link = link

class FileContents:
    def __init__(self, contents:str)->None:
        self.contents = contents

tgz_type = Dict[str,Union[FileLink,FileContents]]
def mk_input(input_tgz:tgz_type)->None:
    """
    Generate a tarball from a hash of file names/contents.
    """
    pcmd(["rm","-fr","run_dir"])
    os.mkdir("run_dir")
    for k in input_tgz.keys():
        val = input_tgz[k]
        fname = os.path.join("run_dir",k)
        if type(val) == FileLink:
            s = os.stat(val.link)
            if s.st_size < FILE_LINK_SIZE:
                pcmd(["cp",val.link,fname])
            else:
                fname += ".link"
                with open(fname,"w") as fd:
                    print(val.link,file=fd)
        elif type(val) == FileContents:
            with open(fname,"w") as fd:
                print(val.contents,file=fd)
        else:
            raise Exception("Bad value to dict input_tgz")
    pcmd(["tar","czf","input.tgz","run_dir"])

def getlinks(input_tgz : str) -> List[Tuple[str,str]]:
    links = []
    tar = tarfile.open(input_tgz, "r:gz")
    for m in tar.getmembers():
        if m.name.endswith(".link"):
            f = tar.extractfile(m)
            if f is not None:
                content = f.read().decode()
                links += [(m.name, content.strip())]
    return links

##################### AUTH #######################

class AuthBase(metaclass=ABCMeta):
    def __init__(self)->None:...
    @abstractmethod
    def __repr__(self)->str:
        ...
    @abstractmethod
    def get_idstr(self)->str:
        ...
    @abstractmethod
    def refresh_token(self)->bool:
        ...
    @abstractmethod
    def get_auth_data(self)->JDict:
        ...
    @abstractmethod
    def get_auth_file(self)->str:
        ...
    @abstractmethod
    def systems_list(self)->List['Machine']:
        ...
    @abstractmethod
    def get_system(self,name:str)->Optional['Machine']:
        ...

class Machine:
    def to_data(self)->JDict:
        data = {}
        for n in dir(self):
            if n.startswith("_"):
                continue
            t = getattr(self, n)
            if type(t) == type(self.to_data):
                continue
            data[n] = t
        return data

    def __init__(self,
            definition_owner : str,
            name : str,
            user : str,
            domain : str,
            queue : str,
            home_dir : ostr = None,
            port : int = 22,
            max_jobs_per_user : int = 1,
            max_jobs : int = 1,
            max_nodes : int = 1,
            scratch_dir : ostr = None,
            work_dir : ostr = None,
            root_dir : str = "/",
            max_run_time : str = "01:00:00",
            max_procs_per_node : int = 16,
            scheduler : str = "SLURM",
            custom_directives : Optional[JDict] = None,
            suffix : str = "jlag")->None:
        self.definition_owner = definition_owner
        self.name = name
        self.user = user
        self.domain = domain
        self.queue = queue

        if home_dir is None:
            self.home_dir = f"/home/{self.user}"
        else:
            self.home_dir = normalize_dir(home_dir)

        self.port = port
        self.max_jobs_per_user = max_jobs_per_user
        self.max_jobs = max_jobs
        self.max_nodes = max_nodes

        if scratch_dir is None:
            self.scratch_dir = f"/scratch/{self.user}"
        else:
            self.scratch_dir = normalize_dir(scratch_dir)
        if work_dir is None:
            self.work_dir = f"/work/{self.user}"
        else:
            self.work_dir = normalize_dir(work_dir)
        self.root_dir = normalize_dir(root_dir)
        self.max_run_time = max_run_time
        self.max_procs_per_node = max_procs_per_node
        self.scheduler = scheduler
        self.custom_directives = custom_directives
        self.suffix = suffix
    def __eq__(self, m:Any)->bool:
        for a in dir(self):
            if a == "to_data":
                continue
            if a.startswith("_"):
                continue
            v1 = getattr(self,a)
            v2 = getattr(m,a)
            if v1 != v2:
                print("Fail for:",a,v1,"!=",v2)
                return False
        return True
    def __repr__(self)->str:
        return f'{self.name}-{self.user}-exec-{self.definition_owner}-{self.suffix}'

def machine_from_data(data:JDict)->Machine:
    m = Machine("", "", "", "", "")
    for k in data:
        setattr(m, k, data[k])
    return m

class JobBase(metaclass=ABCMeta):
    def __init__(self, jetlag:'JetlagBase', jobid:str, jobname:str)->None:
        self.jetlag = jetlag
        self.jobid = jobid
    @abstractmethod
    def get_status(self)->Optional[str]:
        ...
    def get_history(self)->JType:
        return self.jetlag.get_job_history(self.jobid)

    @abstractmethod
    def stop(self)->JType:
        ...
    @abstractmethod
    def show_history(self)->None:
        ...
    @abstractmethod
    def get_result(self, force:bool=True)->JType:
        ...

class JetlagBase(metaclass=ABCMeta):
    def __init__(self, auth:AuthBase, machine:Machine)->None:
        self.auth = auth
        self.machine = machine

    @abstractmethod
    def configure(self)->bool:
        ...
    @abstractmethod
    def get_job_file(self,jobid:Union[str,JobBase],remote_fname:str,local_fname:Optional[str])->bytes:
        ...
    @abstractmethod
    def get_job_file_list(self,jobid:str,dir:str='',recurse:bool=False)->List[str]:
        ...
    @abstractmethod
    def make_dir(self, dir_name:str)->None:
        ...
    @abstractmethod
    def hello_world_job(self, jtype:str='fork')->JobBase:
        ...
    @abstractmethod
    def run_job(self, job_name:str, script_file:str, input_tgz:tgz_type={}, jtype:str='fork',
            nodes:int=1, ppn:int=16, run_time:ostr=None, nx:int=0, ny:int=0, nz:int=0)->JobBase:
        ...
    @abstractmethod
    def get_job_history(self, job_id:str)->JType:
        ...
    @abstractmethod
    def get_access(self,app:str='queue')->List[str]:
        ...
    @abstractmethod
    def set_access(self,userid:str,allow:bool)->bool:
        ...
    #@abstractmethod
    #def get_type(self)->str:
    #    ...
    @abstractmethod
    def file_upload(self, dir_name:str, file_name:str, file_contents:Optional[Union[str,bytes]]=None)->None:
        ...

    def prep_job(self, job_name:str, input_tgz:tgz_type={})->None:
        input_tgz["metadata.txt"] = FileContents(json.dumps({
            "job-name":job_name,
            "jetlag-type":self.get_type(),
        }))
        mk_input(input_tgz)

        links = getlinks("input.tgz")
        for link in links:
            name, origin = link
            assert type(origin) == str
            if name.endswith(".link"):
                # Load the file_links from disk
                auth_file = self.auth.get_auth_file()
                print("auth_file:",auth_file)
                auth_dir = os.path.dirname(auth_file)
                file_links = os.path.join(auth_dir, "file_links.txt")
                if os.path.exists(file_links):
                    with open(file_links, "r") as fd:
                        file_links_data = json.loads(fd.read())
                else:
                    file_links_data = {}

                # If the data in file_links_data is out of date, upload
                st = os.stat(origin)
                if origin not in file_links_data or file_links_data[origin] != st.st_mtime:
                    self.file_upload('{deployment_path}',origin)
                    file_links_data[origin] = st.st_mtime
                    with open(file_links,"w") as fd:
                        fd.write(json.dumps(file_links_data))
