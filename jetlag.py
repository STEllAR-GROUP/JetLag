from typing import List, Tuple, Any, Union, Dict, Optional, cast
from hosts import *
from ser import ser, deser
import sqlite3 as sq3
from tempfile import NamedTemporaryFile
from names import rand_name
import hashlib, base64, re, os
from random import randint
import diagrequests as requests
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
from tasks import run_task, task_status
from here import here
import tarfile
import pwd
from requests.models import Response

FILE_LINK_SIZE = 1e6

ostr = Optional[str]

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

_here = os.path.realpath(".")

baseurl = None
cmd_args = []
time_array : List[Tuple[str,float]] = []
pause_files = 5
pause_time = 30
poll_time = 5

pp = pprint.PrettyPrinter(indent=2)

os.environ["AGAVE_JSON_PARSER"]="jq"

job_done = ["FAILED", "FINISHED", "STOPPED", "BLOCKED"]
status_color = {
    "FAILED" : "red",
    "STOPPED" : "red",
    "BLOCKED" : "magenta",
    "FINISHED" : "green",
    "PENDING" : "cyan",
}
def get_status_color(status : str)->str:
    if status in status_color:
        return status_color[status]
    else:
        return "yellow"

has_color = False

now = time()

JType = Union[Dict[str,'JType'],List['JType'],str,int]

def rm_auth(d : JType)->JType:
    """
    Recurse through arbitrary lists, dicts, etc.
    and remove the 'auth' key from any dict.
    """
    if type(d) == dict:
        r = {}
        for k in d:
            if k == "auth":
                continue
            r[k] = rm_auth(d[k])
        return r
    elif type(d) == list:
        return [rm_auth(x) for x in d]
    else:
        return d

verbose : bool = False
def set_verbose(v : bool) -> None:
    global verbose
    verbose = v


def ago(ts : int)->str:
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


def get_json(response : Response)->Optional[JType]:
    content = response.content
    json : Optional[JType] = None
    try:
        json = cast(JType,response.json())
    except:
        print("content:",content)
        requests.show()
    return json


def from_agave_time(ts : str)->Tuple[datetime,float]:
    from time import mktime, time
    from datetime import datetime
    import re
    # To install: pip install python-dateutil
    from dateutil import tz
    utc_time = ts[-1] == 'Z'
    g = re.search(r'\.\d+',ts)
    if g:
        s = ts[:g.start()]
        frac = float(g.group(0))
    else:
        s = re.sub(r'Z$','',ts)
        frac = 0
    that_tz = tz.gettz("GMT") 
    this_tz = tz.tzlocal()
    val = datetime.strptime(s,"%Y-%m-%dT%H:%M:%S")
    if utc_time:
        val = val.replace(tzinfo=that_tz)
        val = val.astimezone(this_tz)
    return (val, time() - (val.timestamp() + frac))

# Agave/Tapis uses all of these http status codes
# to indicate succes.
success_codes = [200, 201, 202]

def age(fname : str)->float:
    "Compute the age of a file in seconds"
    t1 = os.path.getmtime(fname)
    t2 = time()
    return t2 - t1

def pcmd(cmd : List[str],input : ostr=None,cwd : ostr=None)->Tuple[int, str, str]:
    """
    Generalized pipe command with some convenient options
    """
    if verbose:
        print(colored(' '.join(cmd),"magenta"))
    p = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, universal_newlines=True, cwd=cwd)
    if input is not None:
        if verbose:
            print("send input...")
        out, err = p.communicate(input=input)
    else:
        out, err = p.communicate()
    if verbose:
        print(colored(out,"green"),end='')
    if err != '':
        if verbose:
            print(colored(err,"red"),end='')
    return p.returncode, out, err

def link_filter(data : JType)->JType:
    if type(data) == dict:
        new_dict = {}
        for k in data:
            if k != "_links":
                new_dict[k] = link_filter(data[k])
        return new_dict
    elif type(data) == list:
        new_list = []
        for n in data:
            new_list += [link_filter(n)]
        return new_list
    else:
        return data

def key2(a : Tuple[str,float])->int:
    return int(1e6*a[1])

# Most reliable way to get HOME
home = pwd.getpwuid(os.getuid()).pw_dir

def pause()->None:
    pass

def _pause()->None:
    global time_array
    tmp_dir = os.path.join(home,"tmp","times")
    if len(time_array) == 0:
        os.makedirs(tmp_dir, exist_ok=True)
        time_array = []
        for i in range(pause_files):
            tmp_file = os.path.join(tmp_dir,"t_"+str(i))
            if not os.path.exists(tmp_file):
                with open(tmp_file,"w") as fd:
                    pass
            tmp_age = os.path.getmtime(tmp_file)
            time_array += [(tmp_file,tmp_age)]

    # For some reason, time() doesn't always return
    # a value of now that's consistent with the file system.
    now_file = os.path.join(tmp_dir, "now_file.txt")
    with open(now_file, "w"):
        pass
    now = os.path.getmtime(now_file)

    time_array = sorted(time_array,key=key2)
    oldest_file = time_array[0][1]
    assert oldest_file < now
    delt = oldest_file + pause_time - now
    assert delt < pause_time
    if delt > 0:
        print("sleep",delt,"...",end='',flush=True)
        sleep(delt)
        print("done",flush=True)
    with open(time_array[0][0],"w") as fd:
        pass
    time_array[0] = (time_array[0][0],os.path.getmtime(time_array[0][0]))

def idstr()->str:
    base = ''
    for i in range(ord('a'),ord('z')+1):
        base += chr(i)
    for i in range(ord('A'),ord('Z')+1):
        base += chr(i)
    for i in range(ord('0'),ord('9')+1):
        base += chr(i)
    s = ''
    for i in range(20):
        s += base[randint(0, len(base)-1)]
    return s

def codeme(m : Union[str,bytes]) -> str:
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

def check(response : Response) -> None:
    """
    Called after receiving a response from the requests library to ensure that
    an error was not received.
    """
    if response.status_code not in success_codes:
        # This will show a request saved by
        # the diagrequests package.
        requests.show()
        msg = str(response)
        if response.content is not None:
            msg += response.content.decode()
        raise Exception(msg)

default_agave = os.path.join(home,".agave","current")

def get_current(fname : str)->List[str]:
    ret = []
    if os.path.isdir(fname):
        for f in os.listdir(fname):
            full = os.path.join(fname, f)
            if full == default_agave:
                continue
            if f == "current":
                ret += [full]
            ret += get_current(full)
    return ret

def get_auth_by_fname(fname : str)->'Auth':
    with open(fname,"r") as fd:
        jdata = json.loads(fd.read())
        if "/.tapis/" in fname:
            ut = "tapis"
        elif "/.agave/" in fname:
            ut = "agave"
        else:
            ut = "ssh"
    if 'client' in jdata:
        a = Auth(utype=ut,user=jdata["username"],baseurl=jdata["baseurl"],tenant=jdata["tenantid"],client=jdata['client'])
    else:
        a = Auth(utype=ut,user=jdata["username"],baseurl=jdata["baseurl"],tenant=jdata["tenantid"])
    afile = a.get_auth_file()
    if afile != fname:
        raise Exception("Bad auth file: %s != %s" % (afile, fname))
    return a

def get_auth_sessions()->List[str]:
    names = \
        get_current(os.path.join(home, ".agave")) + \
        get_current(os.path.join(home, ".tapis")) + \
        get_current(os.path.join(home, ".sshcfg")) 
    agave_cache_dir = os.environ.get("AGAVE_CACHE_DIR",None)
    if agave_cache_dir is not None:
        agave_cache_file = os.path.join(agave_cache_dir, "/current")
        if not os.path.exists(agave_cache_file):
            print(f"Invalid setting for environment variable AGAVE_CACHE_DIR: '{agave_cache_dir}'")
            exit(2)
        if agave_cache_file not in names:
            names += [agave_cache_file]
    return names

def get_auth_by_session(name : str)->'Auth':
    sessions = get_auth_sessions()
    auths = []
    idstrs = []
    for session in sessions:
        a = get_auth_by_fname(session)
        idstr = a.get_idstr()
        idstrs += [idstr]
        if name in idstr:
            auths += [a]
    if len(idstrs) == 0:
        print("No sessions have been configured. Please try 'jetlag.py session-create'")
        usage()
    if len(auths) != 1:
        print(f"Name '{name}' does not uniquely identify a session.")
        print("Sessions are:")
        for idstr in idstrs:
            print(" ",idstr)
        usage()

    return auths[0]
    
class Auth:
    """
    The Universal (i.e. Tapis or Agave) authorization
    """
    def __init__(self, utype:str, user:ostr=None, password:ostr=None, baseurl:ostr=None, tenant:ostr=None, client:ostr=None)->None:
        self.client = client
        self.is_valid = False
        if user is not None:
            assert '@' not in user
        assert utype in ['tapis', 'agave', 'ssh'], 'utype="%s"' % utype

        # Fill in the default baseurl
        if baseurl is None:
            if utype == 'agave':
                baseurl = "https://sandbox.agaveplatform.org"
            elif utype == 'ssh':
                baseurl = "ssh"
            else:
                baseurl = "https://api.tacc.utexas.edu"
        elif tenant != "ssh":
            if not re.match(r'^https://', baseurl):
                baseurl = "https://"+baseurl
        
        # Fill in the default tenant
        if tenant is None:
            if utype == 'agave':
                tenant = "sandbox"
            elif utype == 'ssh':
                tenant = "ssh"
            else:
                tenant = "tacc.prod"

        self.client = client
        self.utype = utype
        self.user = user
        self.baseurl = baseurl
        self.tenant = tenant
        self.password = password
        self.auth_data = None

        self.auth_age = None

    def __repr__(self)->str:
        return self.get_idstr()

    def get_idstr(self)->str:
        #idstr = self.utype+"+"+self.tenant+":"+self.user+"@"+self.baseurl
        idstr = self.utype+":"+self.user+":"+re.sub(r'^https://','',self.baseurl)+":"+self.tenant
        if self.client is not None:
            idstr += ":"+self.client
        return idstr

    def get_auth_file(self)->str:
        burl = codeme("~".join([
            self.tenant,
            self.baseurl,
            self.utype,
            self.user
        ]))
        if self.utype == "ssh":
            ut = ".sshcfg"
        else:
            ut = "."+self.utype
        return os.path.join(home, ut, self.user, burl, "current")

    def create_or_refresh_token(self)->None:
        if self.utype == "ssh":
            ssh_data = get_ssh_data()
            if self.baseurl not in ssh_data:
                ssh_data[self.baseurl] = {}
            host_data = ssh_data[self.baseurl]
            if has_host_key(self.baseurl):
                if "stricthostkeychecking" in host_data:
                    set_ssh_data(self.baseurl, "stricthostkeychecking", None)
            else:
                if not "stricthostkeychecking" in host_data:
                    set_ssh_data(self.baseurl, "stricthostkeychecking", "no")
            self.is_valid = True
            return
        auth_file = self.get_auth_file()
        if verbose:
            print(colored("Auth file:","green"), auth_file)
        if os.path.exists(auth_file):
            self.auth_mtime = os.path.getmtime(auth_file)
        if not self.refresh_token():
            self.create_token()

    def get_password(self)->str:
        if self.password is None:
            from getpass import getpass
            self.password = getpass(self.utype[0].upper() + self.utype[1:] + " Password: ")
        return self.password

    def create_token(self)->Optional[JType]:

        if self.utype == "ssh":
            self.is_valid = True
            return None

        auth = (
            self.user,
            self.get_password()
        )

        while True:
            # Create a client name and search to see if it exists
            client_name = rand_name() #"client-"+idstr()
            data = {
                'clientName': client_name,
                'tier': 'Unlimited',
                'description': '',
                'callbackUrl': ''
            }
            url = self.baseurl+'/clients/v2/'+client_name
            response = requests.get(url, auth=auth)
            jdata = get_json(response)['result']
            if response.status_code in [404, 400]:
                break
            check(response)
            assert jdata["name"] == client_name

        url = self.baseurl+'/clients/v2/'
        response = requests.post(url, data=data, auth=auth)
        check(response)
        jdata = response.json()["result"]
        c_key = jdata['consumerKey']
        c_secret = jdata['consumerSecret']

        data = {
            'grant_type':'password',
            'scope':'PRODUCTION',
            'username':self.user,
            'password':self.get_password()
        }
        response = requests.post(self.baseurl+'/token', data=data, auth=(c_key, c_secret))
        jdata = response.json()

        now = time()
        delt = int(jdata["expires_in"])
        ts = now + delt

        fdata = {
            "verify_ssl":requests.verify_ssl,
            "utype":self.utype,
            "client":client_name,
            "tenantid":self.tenant,
            "baseurl":self.baseurl,
            "apisecret":c_secret,
            "apikey":c_key,
            "username":self.user,
            "access_token":jdata['access_token'],
            "refresh_token":jdata["refresh_token"],
            "expires_in":delt,
            "created_at":int(now),
            "expires_at":datetime.utcfromtimestamp(ts).strftime('%c')
        }
        self.auth_data = fdata
        self.save_auth_data()
        self.is_valid = True
        return fdata


    def refresh_token(self):
        """
        This is under construction (i.e. it doesn't work).
        In principle, it can refresh an agave/tapis token.
        """
        if self.utype == "ssh":
            self.is_valid = True
            return

        auth_file = self.get_auth_file()
        if self.auth_data is None:
            self.get_auth_data()
            if self.auth_data is not None and "verify_ssl" in self.auth_data:
                if not self.auth_data["verify_ssl"]:
                    if verbose: 
                        requests.set_ssl(False)
        if not os.path.exists(auth_file):
            return False 
        if age(auth_file) < 30*60:
            self.is_valid = True
            return True

        auth_data = self.get_auth_data()

        # Check that the data in the file
        # is compatible.
        assert auth_data["username"] == self.user, \
            "Incorrect user in auth file '%s' != '%s'" % (auth_data["username"],self.user)

        data = {
          'grant_type': 'refresh_token',
          'refresh_token': auth_data['refresh_token'],
          'scope': 'PRODUCTION'
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        auth = (
            auth_data['apikey'],
            auth_data['apisecret']
        )
        try:
            response = requests.post(
                self.baseurl + '/token', headers=headers, data=data, auth=auth)
            check(response)
            jdata = response.json()
            auth_data["refresh_token"] = jdata["refresh_token"]
            auth_data["access_token"] = jdata["access_token"]

            now = time()
            delt = int(jdata["expires_in"])
            auth_data["expires_in"] = delt
            ts = now + delt
            auth_data["created_at"] = int(now)
            auth_data["expires_at"] = datetime.utcfromtimestamp(ts).strftime('%c')
            self.auth_data = auth_data
            self.save_auth_data()
            if verbose:
                if "client" in self.auth_data:
                    print(colored("Refresh successful for client:","green"),self.auth_data["client"])
                else:
                    print(colored("Refresh successful","green"))
                self.is_valid = True
        except Exception as e:
            print(colored("Exception:","red"),e)
            pass
            self.is_valid = False
        return self.is_valid

    def save_auth_data(self):
        auth_file = self.get_auth_file()
        os.makedirs(os.path.dirname(auth_file), exist_ok=True)

        # Ensure the auth_file exists
        if not os.path.exists(auth_file):
            with open(auth_file,"w"):
                pass

        # Ensure the auth_file permissions
        os.chmod(auth_file, 0o600)

        # Save the verify_ssl state
        if "verify_ssl" not in self.auth_data:
            self.auth_data["verify_ssl"] = requests.verify_ssl,

        # Actually write the auth file
        with open(auth_file,"w") as fd:
            fd.write(json.dumps(self.auth_data))

    def get_auth_data(self):
        auth_file = self.get_auth_file()
        if not os.path.exists(auth_file):
            return None
        auth_age = os.path.getmtime(auth_file)
        if auth_age == self.auth_age:
            return self.auth_data
        self.auth_age = auth_age
        with open(auth_file,"r") as fd:
            contents = fd.read()
            try:
                auth_data = json.loads(contents)
            except:
                os.remove(auth_file)
                raise Exception('Bad Auth Data: '+contents)
        self.auth_data = auth_data
        self.auth_data["auth_file"]=auth_file
        return auth_data

class JetLag:
    def __init__(self,agave_auth,machine=None,machine_user=None,domain=None,port:int=22,
            queue='unknown',max_jobs_per_user:int=1,max_jobs:int=1,
            max_nodes:int=1,scratch_dir="/scratch/{machine_user}",
            work_dir="/work/{machine_user}",home_dir="/home/{machine_user}",
            root_dir="/",max_run_time="01:00:00",max_procs_per_node=16,
            min_procs_per_node=16,allocation="N/A",
            scheduler="SLURM",custom_directives=None,
            owner=None,suffix=None,
            priv_key=None, jetlag_id=None):

        self.agave_auth = agave_auth

        if jetlag_id is not None:
            g = re.match(r'^(\w+)-(\w+)-(\w+)$', jetlag_id)
            assert g, "Invalid jetlag_id = '%s'" % jetlag_id
            assert machine is None or machine == g.group(1)
            assert machine_user is None or machine_user == g.group(2)
            assert owner is None or owner == g.group(3)
            machine = g.group(1)
            machine_user = g.group(2)
            owner = g.group(3)

        if owner is not None:
            self.owner = owner
        else:
            self.owner = agave_auth.get_auth_data()["username"]
        self.machine = machine
        self.domain = domain
        self.port = port
        self.allocation = allocation
        self.max_run_time = max_run_time
        self.machine_user = machine_user
        self.work_dir = self.fill(work_dir)
        self.home_dir = self.fill(home_dir)
        self.scratch_dir = self.fill(scratch_dir)
        self.root_dir = self.fill(root_dir)
        self.queue = queue
        self.agave_user = self.agave_auth.get_auth_data()["username"]
        self.scheduler = scheduler
        self.custom_directives = custom_directives
        self.min_procs_per_node = min_procs_per_node
        self.max_procs_per_node = max_procs_per_node
        self.max_jobs_per_user = max_jobs_per_user
        self.max_jobs = max_jobs
        self.max_nodes = max_nodes
        self.utype = self.agave_auth.utype
        if suffix is None:
            self.suffix = self.owner
        else:
            assert re.match(r'^\w+$', suffix), "Bad suffix '%s'" % suffix
            self.suffix = self.owner + "-" + suffix

        # Does it matter that we don't support machines/users with hyphens in their names?
        if machine is not None:
            assert re.match(r'^\w+$', self.machine), "Unsupported character in machine name '%s'" % self.machine
            assert re.match(r'^\w+$', self.owner), "Unsupported character in owner name '%s'" % self.owner
            assert re.match(r'^\w+$', self.machine_user), "Unsupported character in machine_user '%s'" % self.machine_user

        self.app_name = self.fill("{machine}-{machine_user}_queue_{suffix}")
        self.fork_app_name = self.fill("{machine}-{machine_user}_fork_{suffix}")
        self.jetlag_id = self.fill("{machine}-{machine_user}-{suffix}")
        self.storage_id = self.fill('{machine}-{machine_user}-storage-{suffix}')
        self.execm_id = self.fill('{machine}-{machine_user}-exec-{suffix}')
        self.forkm_id = self.fill('{machine}-{machine_user}-fork-{suffix}')
        self.app_id = self.fill("{machine}-{machine_user}_queue_{suffix}-1.0.0")
        self.fork_app_id = self.fill("{machine}-{machine_user}_fork_{suffix}-1.0.0")
        self.deployment_path = self.fill("new-{utype}-deployment")

        if priv_key is None:
            key_dir = os.path.dirname(self.agave_auth.get_auth_file())
            priv_key = os.path.join(key_dir, "id_rsa")
            if verbose:
                print(colored("Using key:","green"),priv_key)
        else:
            key_dir = os.path.dirname(priv_key)

        pub_key = priv_key + '.pub'
        if not os.path.exists(priv_key):
            os.makedirs(key_dir,exist_ok=True)
            if verbose:
                print(colored("Creating key:","green"),priv_key)
            r, o, e = pcmd(["ssh-keygen","-m","PEM","-t","rsa","-f",priv_key,"-P",""])

        if os.path.exists(pub_key):
            with open(pub_key, "r") as fd:
                self.pub_key = fd.read().strip()
        if os.path.exists(priv_key):
            with open(priv_key, "r") as fd:
                self.priv_key = fd.read().strip()

        self.auth = {
            "username" : self.machine_user,
            "publicKey" : self.pub_key,
            "privateKey" : self.priv_key,
            "type" : "SSHKEYS"
        }

        self.access_token = self.agave_auth.get_auth_data()["access_token"]
        self.apiurl = self.agave_auth.get_auth_data()["baseurl"]
        self.app_version = "1.0.0"
        if self.utype == "tapis":
            self.jobs_dir = self.fill('tjob/{agave_user}')
        elif self.utype == 'ssh':
            self.jobs_dir = self.fill('sjob/{agave_user}')
        else:
            self.jobs_dir = self.fill('ajob/{agave_user}')

        # This JetLag object can't be used for job submission
        if machine is None:
            return

        if domain is None:
            # Load data from an existing machine
            exec_data = self.get_exec()
            self.domain = exec_data["site"]
            self.port = exec_data["login"]["port"]
            self.queue = exec_data["queues"][0]["name"]

    def ssh_job(self, job):
        exec_txt = os.path.join(self.jetlag_dir(), "execution.txt")
        with open(exec_txt,"r") as fd:
            exec_data = json.loads(fd.read())
        app_txt = os.path.join(self.jetlag_dir(), "app.txt")
        with open(app_txt,"r") as fd:
            app_data = json.loads(fd.read())


        job_dir = os.path.join(exec_data["workDir"], job["name"])
        self.make_dir(job_dir)

        wrapper = os.path.join(app_data["deploymentPath"],app_data["templatePath"])
        tfile = NamedTemporaryFile()
        with open(tfile.name, "w") as fd:
            print(f"cp {wrapper} {job_dir}/job-run.sh",file=fd)
            print(f"cd {job_dir}",file=fd)
            print(f"exec > job.out 2>job.err",file=fd)
            jobpars = job["parameters"]
            for par in jobpars:
                parval = jobpars[par]
                print(f"perl -p -i -e 's/\${{{par}}}/{parval}/g' job-run.sh",file=fd)
            print(f"bash {job_dir}/job-run.sh",file=fd)
        with open(tfile.name, "r") as fd:
            c = fd.read()
        self.make_dir(job_dir)
        self.file_upload(job_dir,"job-exec.sh",c)
        return str(self.ssh_cmd_thread(["bash",f"{job_dir}/job-exec.sh"]))


    def fill(self, obj : JType)->JType:
        if obj is None:
            return obj
        elif type(obj) == str:
            s = ''
            pos = 0
            for p in re.finditer(r'(\$?){(\w+)}', obj):
                s += obj[pos:p.start()]
                if p.group(1) == '$':
                    s += p.group(0)
                else:
                    s += str(getattr(self, p.group(2)))
                pos = p.end()
            if pos == 0:
                return obj
            else:
                return s + obj[pos:]
        elif type(obj) == list:
            li = []
            for item in obj:
                li += [self.fill(item)]
            return li
        elif type(obj) == dict:
            di = {}
            for key in obj:
                di[key] = self.fill(obj[key])
            return di
        else:
            return obj

    def get_headers(self,data=None):
        """
        We need basically the same auth headers for
        everything we do. Factor out their initialization
        to a common place.
        """
        self.agave_auth.refresh_token()
        self.access_token = self.agave_auth.get_auth_data()["access_token"]
        headers = {
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Authorization': self.fill('Bearer {access_token}'),
            'Connection': 'keep-alive',
            'User-Agent': 'python-requests/2.22.0',
        }
        if data is not None:
            assert type(data) == str
            headers['Content-Type'] = 'application/json'
            headers['Content-Length'] = str(len(data))
        return headers

    def check_machine(self,machine):
        """
        Checks that we can do a files list on the machine.
        This proves (or disproves) that we have auth working.
        """
        if verbose:
            print(colored("Checking we can list files from machine:","green"),machine)
        headers = self.get_headers()
        params = (('limit','5'),('offset','0'),)
        url = self.fill('{apiurl}/files/v2/listings/system/'+machine+'/')
        pause()
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 404:
            if verbose:
                print(colored("Received 404 from URL","red"),url)
            return False
        check(response)
        file_data = response.json()["result"]
        n = 0
        for file in file_data:
            if verbose:
                print(colored("File:","blue"),file["name"])
            n += 1
        assert n > 0
        return True
    
    def mk_storage(self,force=False):

        storage_id = self.storage_id

        if verbose:
            print(colored("Creating Storage Machine:","green"),storage_id)

        port = int(self.port)

        storage = self.fill({
            "id" : storage_id,
            "name" : "{machine} storage ({machine_user})",
            "description" : "The {machine} computer",
            "site" : "{domain}",
            "type" : "STORAGE",
            "storage" : {
                "host" : "{machine}.{domain}",
                "port" : port,
                "protocol" : "SFTP",
                "rootDir" : "{root_dir}",
                "homeDir" : "{home_dir}",
                "auth" : self.auth,
                "publicAppsDir" : "{home_dir}/apps"
            }
        })
        if self.is_ssh():
            self.store_data(storage, "storage.txt")
            return

        if not force:
            headers = self.get_headers()
            response = requests.get(
                self.fill('{apiurl}/systems/v2/{storage_id}'), headers=headers)
            print(self.fill('{apiurl}/systems/v2/{storage_id}'))
            check(response)

        if (force or not self.check_machine(storage_id)):
            json_storage = json.dumps(storage)
            headers = self.get_headers(json_storage)
            response = requests.post(
                self.fill('{apiurl}/systems/v2/'), headers=headers, data=json_storage)
            check(response)
            assert self.check_machine(storage_id)

    def mk_execution(self,force=False):

        if verbose:
            print(colored("Creating Execution Machine:","green"),self.execm_id)

        execm = self.fill({
            "id" : self.execm_id,
            "name" : "{machine} exec ({machine_user})",
            "description" : "The {machine} execution computer",
            "site" : "{domain}",
            "public" : False,
            "status" : "UP",
            "type" : "EXECUTION",
            "executionType": "HPC",
            "scheduler" : "{scheduler}",
            "environment" : None,
            "scratchDir" : "{scratch_dir}",
            "workDir" : "{work_dir}",
            "login" : {
                "auth" : self.auth,
                "host" : "{machine}.{domain}",
                "port" : self.port,
                "protocol" : "SSH"
            },
            "maxSystemJobs" : "{max_jobs}",
            "maxSystemJobsPerUser" : "{max_jobs_per_user}",
            "queues" : [
              {
                "name" : "{queue}",
                "default" : True,
                "maxJobs" : "{max_jobs}",
                "maxNodes" : "{max_nodes}",
                "maxProcessorsPerNode" : "{max_procs_per_node}",
                "minProcessorsPerNode" : "{min_procs_per_node}",
                "maxRequestedTime" : "{max_run_time}"
              }
            ],
            "storage" : {
                "host" : "{machine}.{domain}",
                "port" : self.port,
                "protocol" : "SFTP",
                "rootDir" : "{root_dir}",
                "homeDir" : "{home_dir}",
                "auth" : self.auth
            }
        })
        if self.is_ssh():
            self.store_data(execm, "execution.txt")
            return

        forkm = copy(execm)
        forkm["id"] = self.forkm_id
        forkm["scheduler"] = "FORK"
        forkm["executionType"] = "CLI"

        if self.custom_directives is not None:
            for q in execm["queues"]:
                q["customDirectives"] = self.fill(self.custom_directives)

        assert execm["scheduler"] != "FORK"

        # EXEC
        if not force:
            headers = self.get_headers()
            response = requests.get(
                self.fill('{apiurl}/systems/v2/{execm_id}'), headers=headers)
            print(self.fill('{apiurl}/systems/v2/{execm_id}'))
            check(response)

        if force or not self.check_machine(self.exec_id):
            json_execm = json.dumps(execm)
            headers = self.get_headers(json_execm)
            response = requests.post(
                self.fill('{apiurl}/systems/v2/'), headers=headers, data=json_execm)
            check(response)
            assert self.check_machine(self.execm_id)

        # FORK
        if not force:
            headers = self.get_headers()
            response = requests.get(
                self.fill('{apiurl}/systems/v2/{forkm_id}'), headers=headers)
            print(self.fill('{apiurl}/systems/v2/{forkm_id}'))
            check(response)

        if force or not self.check_machine(self.forkm_id):
            json_forkm = json.dumps(forkm)
            headers = self.get_headers(json_forkm)
            response = requests.post(
                self.fill('{apiurl}/systems/v2/'), headers=headers, data=json_forkm)
            check(response)
            assert self.check_machine(self.forkm_id)

    def mk_app(self,force=True):

        wrapper = """#!/bin/bash
        export AGAVE_JOB_NODE_COUNT=${AGAVE_JOB_NODE_COUNT}
        export AGAVE_JOB_PROCESSORS_PER_NODE=${AGAVE_JOB_PROCESSORS_PER_NODE}
        export nx=${nx}
        export ny=${ny}
        export nz=${nz}
        sh -c "${HOME}/exe/${script_name}.sh" """

        app_name = self.app_name
        app_version = self.app_version
        wrapper_file = app_name + "-wrapper.txt"
        test_file = app_name + "-test.txt"

        app_id = self.app_id
        app = self.fill({
            "name" : app_name,
            "version" : app_version,
            "label" : app_name,
            "shortDescription" : app_name,
            "longDescription" : app_name,
            "deploymentSystem" : "{storage_id}",
            "deploymentPath" : "{deployment_path}",
            "templatePath" : wrapper_file,
            "testPath" : test_file,
            "executionSystem" : "{execm_id}",
            "executionType" : "HPC",
            "parallelism" : "PARALLEL",
            "allocation": "{allocation}",
            "modules":[],
            "inputs":[
                {   
                    "id":"input tarball",
                    "details":{  
                        "label":"input tarball",
                        "description":"",
                        "argument":None,
                        "showArgument":False
                    },
                    "value":{  
                        "default":"",
                        "order":0,
                        "required":False,
                        "validator":"",
                        "visible":True
                    }
                }   
            ],
            "parameters":[
                {
                  "id": "simagename",
                  "value": {
                    "visible": True,
                    "required": False,
                    "type": "string",
                    "order": 0,
                    "enquote": False,
                    "default": "ubuntu",
                    "validator": None
                  },
                  "details": {
                    "label": "Singularity Image",
                    "description": "The Singularity image to run: swan, funwave",
                    "argument": None,
                    "showArgument": False,
                    "repeatArgument": False
                  },
                  "semantics": {
                    "minCardinality": 0,
                    "maxCardinality": 1,
                    "ontology": []
                  }
                },
                {
                  "id": "needs_props",
                  "value": {
                    "visible": True,
                    "required": False,
                    "type": "string",
                    "order": 0,
                    "enquote": False,
                    "default": "ubuntu",
                    "validator": None
                  },
                  "details": {
                    "label": "Needs Properties",
                    "description": "Properties needed before the job runs",
                    "argument": None,
                    "showArgument": False,
                    "repeatArgument": False
                  },
                  "semantics": {
                    "minCardinality": 0,
                    "maxCardinality": 1,
                    "ontology": []
                  }
                },
                {
                  "id": "sets_props",
                  "value": {
                    "visible": True,
                    "required": False,
                    "type": "string",
                    "order": 0,
                    "enquote": False,
                    "default": "ubuntu",
                    "validator": None
                  },
                  "details": {
                    "label": "Sets Properties",
                    "description": "Properties set after the job runs",
                    "argument": None,
                    "showArgument": False,
                    "repeatArgument": False
                  },
                  "semantics": {
                    "minCardinality": 0,
                    "maxCardinality": 1,
                    "ontology": []
                  }
                },
                {
                  "id": "nx",
                  "value": {
                    "visible": True,
                    "required": False,
                    "type": "number",
                    "order": 0,
                    "enquote": False,
                    "default": 0,
                    "validator": None
                  },
                  "details": {
                    "label": "NX",
                    "description": "Processors in the X direction",
                    "argument": None,
                    "showArgument": False,
                    "repeatArgument": False
                  },
                  "semantics": {
                    "minCardinality": 0,
                    "maxCardinality": 1,
                    "ontology": []
                  }
                },
                {
                  "id": "ny",
                  "value": {
                    "visible": True,
                    "required": False,
                    "type": "number",
                    "order": 0,
                    "enquote": False,
                    "default": 0,
                    "validator": None
                  },
                  "details": {
                    "label": "NY",
                    "description": "Processors in the Y direction",
                    "argument": None,
                    "showArgument": False,
                    "repeatArgument": False
                  },
                  "semantics": {
                    "minCardinality": 0,
                    "maxCardinality": 1,
                    "ontology": []
                  }
                },
                {
                  "id": "nz",
                  "value": {
                    "visible": True,
                    "required": False,
                    "type": "number",
                    "order": 0,
                    "enquote": False,
                    "default": 0,
                    "validator": None
                  },
                  "details": {
                    "label": "NZ",
                    "description": "Processors in the Z direction",
                    "argument": None,
                    "showArgument": False,
                    "repeatArgument": False
                  },
                  "semantics": {
                    "minCardinality": 0,
                    "maxCardinality": 1,
                    "ontology": []
                  }
                },
                {
                  "id": "script_name",
                  "value": {
                    "visible": True,
                    "required": False,
                    "type": "string",
                    "order": 0,
                    "enquote": False,
                    "default": "hello",
                    "validator": r"^\S+$"
                  },
                  "details": {
                    "label": "script_name",
                    "description": "Script to run from ~/exe",
                    "argument": None,
                    "showArgument": False,
                    "repeatArgument": False
                  },
                  "semantics": {
                    "minCardinality": 1,
                    "maxCardinality": 1,
                    "ontology": []
                  }
                }
            ],
            "outputs":[  
                {  
                    "id":"Output",
                    "details":{  
                        "description":"The output",
                        "label":"tables"
                    },
                    "value":{  
                        "default":"output.tgz",
                        "validator": None
                    }
                }
            ]
        })

        forkm_id = self.forkm_id
        fork_app_name = self.fork_app_name

        fork_app_id = self.fork_app_id
        forkapp = copy(app)
        forkapp["name"] = fork_app_name
        forkapp["executionSystem"] = forkm_id
        forkapp["executionType"] = "CLI"

        app = self.fill(app)
        forkapp = self.fill(forkapp)

        self.make_dir('{deployment_path}')
        self.make_dir(self.jobs_dir)

        home_dir = self.home_dir

        self.file_upload('{deployment_path}',wrapper_file, wrapper)
        self.file_upload('{deployment_path}',test_file,wrapper_file)
        if self.is_ssh():
            assert app_id is not None
            app["id"] = app_id
            self.store_data(app, "app.txt")
            return

        if verbose:
            print(colored("Make Queue App:","green"),app["name"])
        data = json.dumps(app)
        headers = self.get_headers(data)
        with open("json.txt", "w") as ff:
            print(data, file=ff)
        response = requests.post(self.fill('{apiurl}/apps/v2/'), headers=headers, data=data)
        check(response)

        if verbose:
            print(colored("Make Fork App:","green"),forkapp["name"])
        data = json.dumps(forkapp)
        headers = self.get_headers(data)
        response = requests.post(self.fill('{apiurl}/apps/v2/'), headers=headers, data=data)
        check(response)

    def make_dir(self, dir_name):
        """
        Create a directory relative to the home dir on the remote machine.
        """
        assert not re.match(r'^agave:',dir_name)
        if self.is_ssh():
            self.ssh_cmd(["mkdir","-p",dir_name])
            return
        dir_name = self.fill(dir_name)
        if verbose:
            print(colored("Making Directory:","green"), dir_name)
        data = self.fill(json.dumps({"action": "mkdir", "path": dir_name}))
        headers = self.get_headers(data)
        pause()
        response = requests.put(
            self.fill('{apiurl}/files/v2/media/system/{storage_id}/'), headers=headers, data=data)
        check(response)

    def file_upload(self, dir_name, file_name, file_contents=None):
        """
        Upload a file to a directory. The variable dir_name is relative
        to the home directory.
        """
        dir_name = self.fill(dir_name)
        file_name = self.fill(file_name)
        if verbose:
            if dir_name == "":
                dest = "."
            else:
                dest = dir_name
            print(colored("Uploading file:","green"),file_name,colored("to:","green"),dest)
        #file_contents = self.fill(file_contents)

        if self.is_ssh():
            if file_contents is None:
                self.scp_cmd([file_name,self.get_machine()+":"+dest+"/"+file_name])
            else:
                tfile  = NamedTemporaryFile()
                with open(tfile.name, "w") as fw:
                    fw.write(file_contents)
                if dest != ".":
                    self.ssh_cmd(["mkdir","-p",dest])
                self.scp_cmd([tfile.name,self.get_machine()+":"+dest+"/"+file_name])
            return

        if file_contents is None:
            with open(file_name, "rb") as fd:
                file_contents = fd.read()
        headers = self.get_headers()
        files = self.fill({
            'fileToUpload': (file_name, file_contents)
        })
        url = self.fill('{apiurl}/files/v2/media/system/{storage_id}/'+dir_name)
        pause()
        response = requests.post(url, headers=headers, files=files)
        check(response)

    def hello_world_job(self, jtype='fork',sets_props={},needs_props={}, sleep_time=1):
        """
        Create and send a "Hello World" job to make
        sure that the system is working.
        """
        input_tgz = {}

        return self.run_job('hello-world', input_tgz, jtype=jtype, run_time="00:01:00", sets_props=sets_props, needs_props=needs_props)

    def run_job(self, job_name, input_tgz=None, jtype='fork', nodes=0, ppn=0, run_time=None, sets_props={}, needs_props={}, nx=0, ny=0, nz=0, script_name='helloworld'):
        """
        Run a job. It must have a name and an input tarball. It will default
        to running in a queue, but fork can also be requested. Specifying
        the run-time is a good idea, but not required.
        """
        if ppn == 0:
            ppn = int(self.fill("{max_procs_per_node}"))
        if nodes == 0:
            nodes = ceil(nx*ny*nz/ppn)

        if nx != 0 or ny != 0 or nz != 0:
            assert nx != 0 and ny != 0 and nz != 0
            assert nx*ny*nz <= ppn*nodes

        if nodes == 0:
            nodes = 1

        max_ppn = int(self.fill("{max_procs_per_node}"))
        assert ppn <= max_ppn, '%d <= %d' % (ppn, max_ppn)
        assert ppn >= 1
        assert nodes >= 1

        for k in sets_props:
            for m in self.get_meta(k):
                print("Property '%s' is already set" % k)
                return None

        self.agave_auth.refresh_token()

        if input_tgz is not None:
            mk_input(input_tgz)

            links = getlinks("input.tgz")
            for link in links:
                name, origin = link
                assert type(origin) == str
                if name.endswith(".link"):
                    # Load the file_links from disk
                    auth_file = self.agave_auth.get_auth_file()
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

        if run_time is None:
            run_time = self.max_run_time

        digits = 10
        max_val = 9e9
        while True:
            jid = idstr()
            tmp_job_name = job_name+"-"+jid
            status = self.job_status(tmp_job_name)
            if status is None:
                job_name = tmp_job_name
                break

        for k in sets_props:
            self.set_meta({"name":k,"value":job_name})

        url = self.fill("agave://{storage_id}/{jobs_dir}/"+job_name+"/")
        self.make_dir(self.jobs_dir)
        job_dir = self.jobs_dir+'/'+job_name+'/'
        self.make_dir(job_dir)
        self.file_upload(job_dir,"input.tgz")

        job = self.fill({
            "name":job_name,
            "appId": "{fork_app_id}",
            "batchQueue": "{queue}",
            "maxRunTime": str(run_time),
            "nodeCount": nodes,
            "processorsPerNode": ppn,
            "archive": False,
            "archiveSystem": "{storage_id}",
            "inputs": {
                "input tarball": url + "input.tgz"
            },
            "parameters": {
                "sets_props":",".join(sets_props),
                "needs_props":",".join(sets_props),
                "nx":nx,
                "ny":ny,
                "nz":nz,
                "script_name":script_name
            },
            "notifications": []
        })

        if jtype == 'fork':
            job['appId'] = self.fork_app_id
        elif jtype == 'queue':
            job['appId'] = self.app_id
        else:
            raise Exception("jtype="+jtype)
        
        notify = None

        if notify is not None:
            for event in job_done:
                job["notifications"] += [
                    {
                        "url":notify,
                        "event":event,
                        "persistent": True,
                        "policy": {
                            "retryStrategy": "DELAYED",
                            "retryLimit": 3,
                            "retryRate": 5,
                            "retryDelay": 5,
                            "saveOnFailure": True
                        }
                    }
                ]

        ready = True
        for k in needs_props:
            assert re.match(r'^property-\w+$',k), '"'+k+'"'
            has_k = False
            for m in self.get_meta(k):
                if m["value"] == "READY":
                    has_k = True
                    break
            if not has_k:
                ready = False
                break

        if ready:
            data = json.dumps(job)
            headers = self.get_headers(data)
            if self.is_ssh():
                job_id = self.ssh_job(job)
            else:
                response = requests.post(self.fill('{apiurl}/jobs/v2/'), headers=headers, data=data)
                check(response)
                rdata = response.json()
                job_id = rdata["result"]["id"]
    
            if verbose:
                print(colored("Job ID:","green"), job_id)
            data = {
                "jobid":job_id,
                "needs_props":list(needs_props),
                "sets_props":list(sets_props),
                "jetlag_id":self.jetlag_id
            }
            meta = {
                "name":"jobdata-"+job_name,
                "value":data
            }
            self.set_meta(meta)
            return RemoteJob(self, job_id=job_id, job_name=job_name)
        else:
            data = {
                "job": job,
                "needs_props":list(needs_props),
                "sets_props":list(sets_props),
                "jetlag_id":self.jetlag_id
            }
            meta = {
                "name":"jobdata-"+job_name,
                "value":data
            }
            self.set_meta(meta)
            return RemoteJob(self, job_name=job_name)

#    def job_status(self, job_id):
#        if self.is_ssh():
#            ret = task_status(job_id)
#            here("JOB_STATUS:",ret)
#            return ret
#        else:
#            here("Not an ssh job!")

#        headers = self.get_headers()
#        # Rion says this is a db lookup, so no pause is needed here
#        # pause()
#        response = requests.get(self.fill("{apiurl}/jobs/v2/")+job_id, headers=headers)
#        if response.status_code == 404:
#            return None
#        check(response)
#        jdata = response.json()["result"]
#        return jdata

    def apps_list(self):
        headers = self.get_headers()
        response = requests.get(self.fill("{apiurl}/apps/v2/"), headers=headers)
        check(response)
        jdata = response.json()["result"]
        return jdata

    def jetlag_ids(self):
        if self.is_ssh():
            ids = []
            exec_dir = os.path.join(home, ".sshcfg", "execution")
            for m in os.listdir(exec_dir):
                full = os.path.join(exec_dir, m, "execution.txt")
                with open(full, "r") as fd:
                    jdata = json.loads(fd.read())
                    mid = re.sub('-exec-','-',jdata['id'])
                    ids += [mid]
            return ids
        execms = {}
        storms = {}
        forkms = {}
        forks = {}
        queues = {}
        for s in self.systems_list():
            g = re.match(r'^(\w+)-(\w+)-(storage|exec|fork)-(\w+)(?:-(\w+)|)$', s['id'])
            if g:
                key = "%s-%s-%s" % (g.group(1), g.group(2), g.group(4))
                if g.group(3) == "exec":
                    execms[key] = 1
                elif g.group(3) == "storage":
                    storms[key] = 1
                else:
                    forkms[key] = 1
        for a in self.apps_list():
            # shelob-funwave_fork_tg457049-1.0.0
            g = re.match(r'^(\w+)-(\w+)_(fork|queue)_(\w+)-(\d+\.\d+\.\d+)', a['id'])
            if g:
                key = "%s-%s-%s" % (g.group(1), g.group(2), g.group(4))
                if g.group(3) == 'fork':
                    assert key not in forks
                    forks[key] = a['id']
                else:
                    assert key not in queues
                    queues[key] = a['id']
        jetlag_ids = []
        for k in execms:
            if k in storms and k in forkms and k in forks and k in queues:
                jetlag_ids += [k]
        return jetlag_ids

    def poll(self):
        for data in self.get_meta('jobdata-.*'):
            g = re.match(r'jobdata-(.*)',data['name'])
            job_name = g.group(1)
            m = data["value"]
            if "jobid" in m:
                done = False
                success = True
                jstat = self.job_status(m["jobid"])
                if jstat is not None:
                    m["status"] = jstat["status"]
                else:
                    if verbose:
                        print(colored("Deleting missing job:","red"),m["jobid"])
                    self.del_meta(data)
                    continue
                if m["status"] == "FINISHED":
                    done = True
                    try:
                        f = self.jlag.get_file(m["jobid"],"run_dir/return_code.txt")
                    except:
                        f = b'EXIT(616)'
                    g = re.match("EXIT\((\d+)\)",f.decode())
                    rc = int(g.group(1))
                    if rc != 0:
                        success = False
                elif m["status"] in job_done:
                    done = True

                if done and m["sets_props"] is not None and m["sets_props"] != "null":
                    if success:
                        for k in m["sets_props"]:
                            pm = {
                                "name" : k,
                                "value" : "READY"
                            }
                            if verbose:
                                print("'%s' is ready" % k)
                            self.set_meta(pm)
                    else:
                        for k in m["sets_props"]:
                            for m in self.get_meta(k):
                                self.del_meta(m)

                if done:
                    headers = self.get_headers()
                    pause()
                    jdata = self.job_status(m["jobid"])
                    if "inputs" not in jdata:
                        here("Missing inputs:",jdata)
                        continue
                    fname = jdata['inputs']['input tarball']
                    if self.utype == "tapis":
                        assert type(fname) == str, fname
                    else:
                        assert type(fname) == list, fname
                        fname = fname[0]
                    jg = re.match(r'^agave://([\w-]+)/(.*)/input\.tgz$',fname)
                    assert jg is not None, fname
                    jmach = jg.group(1)
                    jdir = jg.group(2)
                    jloc = jmach+'/'+jdir
                    if verbose:
                        print(colored("Cleanup: ","yellow"),jloc,"...",end='',flush=True,sep='')
                    pause()
                    try:
                        if self.is_ssh():
                            here(jloc)
                            exit(0)
                        else:
                            response = requests.delete(self.fill('{apiurl}/files/v2/media/system/')+jloc, headers=headers)
                            if response.status_code in success_codes:
                                if verbose:
                                    print("done")
                                self.del_meta(data)
                            elif response.status_code in [404, 500]:
                                if verbose:
                                    print("File gone (status_code=%d)" % response.status_code)
                                self.del_meta(data)
                            else:
                                if verbose:
                                    print("Failed (status_code=%d)" % response.status_code)
                    except requests.exceptions.ConnectionError as ce:
                        if verbose:
                            print("...timed out")

            elif "job" in m:
                ready = True
                for k in m["needs_props"]:
                    has_k = False
                    if k == 'property-':
                        continue
                    for pm in self.get_meta(k):
                        if pm["value"] == "READY":
                            has_k = True
                    if not has_k:
                        ready = False
                        if verbose:
                            print("  waiting for:",k)
                if ready:
                    job = m["job"]
                    job_data = json.dumps(job)
                    headers = self.get_headers(job_data)
                    pause()
                    response = requests.post(self.fill('{apiurl}/jobs/v2/'), headers=headers, data=job_data)
                    check(response)
                    rdata = response.json()
                    job_id = rdata["result"]["id"]
            
                    if verbose:
                        print(colored("Job ID:","green"), job_id)
                    m["jobid"] = job_id
                    del m["job"]
                    self.set_meta(data)

    def del_meta(self, data):
        if self.is_ssh():
            db = self.get_db()
            db.execute("delete from meta where uuid = %d" % data["uuid"])
            db.execute("commit");
            return
        headers = self.get_headers()
        uuid = data['uuid']
        response = requests.delete(
            self.fill('{apiurl}/meta/v2/data/')+uuid, headers=headers, verify=False)
        check(response)
        res = self.get_meta(data["name"])
        # assert len(res)==0, "Failed to delete uuid: %s" % uuid

    def set_meta(self, data):
        assert "name" in data
        assert "value" in data
        assert "'" not in data["name"]
        if self.is_ssh():
            db = self.get_db()
            for row in self.get_meta(data["name"]):
                self.del_meta(row)
            sqlstmt = "insert into meta (name,value) values ('%s','%s')" % (data["name"], ser(data["value"]))
            db.execute(sqlstmt)
            db.execute('commit;')
            return

        n = len(data.keys())
        assert n >= 2 and n <= 3

        mlist = self.get_meta(data["name"])

        headers = self.get_headers()
        # This is wrong
        # headers['Content-Type'] = 'application/json'

        files = {
            'fileToUpload': ('meta.txt', json.dumps(data)),
        }
        
        response = requests.post(
            self.fill('{apiurl}/meta/v2/data/'),
            headers=headers, files=files)
        check(response)
        jdata = response.json()
        data["uuid"] = jdata["result"]["uuid"]

        for m in mlist:
            if data["uuid"] == m["uuid"]:
                # This doesn't happen
                continue
            self.del_meta(m)

    def get_db(self):
        db_dir = os.path.join(home, ".sshcfg", self.agave_auth.user)
        if not os.path.exists(db_dir):
            os.makedirs(db_dir,exist_ok=True)
        db_file = os.path.join(db_dir, "sqlite.db")
        db_exists = os.path.exists(db_file)
        db = sq3.connect(db_file)
        if not db_exists:
            db.execute("create table meta (name text, value text, uuid integer primary key autoincrement)")
        return db.cursor()

    def get_meta(self, name):
        if self.is_ssh():
            name = re.sub(r'\.\*','%',name)
            db = self.get_db()
            sqlstmt = "select name, value, uuid from meta where name like '%s'" % name
            result = []
            for row in db.execute(sqlstmt):
                a = 3
                result += [{
                    "name" : row[0],
                    "value": deser(row[1]),
                    "uuid" : row[2]
                    }]
            return result
        headers = self.get_headers()
        
        params = (
            ('q', '{"name":"'+name+'"}'),
            ('limit', '10000'),
        )
        
        response = requests.get(
            self.fill('{apiurl}/meta/v2/data'), headers=headers, params=params)
        check(response)

        result = response.json()["result"]
        result2 = []
        for r in result:
            m = {}
            for k in ["name","value","uuid"]:
                m[k] = r[k]
            result2 += [m]
        return result2

    def get_system(self,name):
        if self.is_ssh():
            name = self.fill(name)
            ddir = os.path.join(home, ".sshcfg", "id", name)
            for p in os.listdir(ddir):
                with open(os.path.join(ddir, p),"r") as fd:
                    return json.loads(fd.read())
            return {}
        sname = self.fill(name)
        if verbose:
            print(colored("System:","green"),sname)
        headers = self.get_headers()
        response = requests.get(
            self.fill('{apiurl}/systems/v2/'+sname), headers=headers)
        if response.status_code == 404:
            return None
        check(response)
        json_data = response.json()
        json_data = json_data["result"]
        return json_data

    def get_storage(self):
        return self.get_system("{storage_id}")

    def get_exec(self):
        return self.get_system("{execm_id}")

    def systems_list(self):
        headers = self.get_headers()
        response = requests.get(self.fill("{apiurl}/systems/v2/"), headers=headers)
        check(response)
        jdata = response.json()["result"]
        return jdata

    def job_status(self, job_id):
        if self.is_ssh():
            ret = task_status(job_id)
            here()
            for job_data in self.get_meta("jobid-"+job_id):
                pp.pprint(job_data)
            here()
            if ret is None:
                jkey = 'jobdata-'+job_id
                for meta in self.get_meta(jkey):
                  ret = task_status(meta["value"]["job_id"])
                  break
            return ret

        headers = self.get_headers()
        response = requests.get(self.fill("{apiurl}/jobs/v2/")+job_id, headers=headers)
        if response.status_code == 404:
            return None
        check(response)
        jdata = response.json()["result"]
        return jdata

    def configure(self):
        """
        Completely configure the univeral system
        starting from ssh keys.
        """
        self.mk_storage(force=True)
        self.mk_execution(force=True)
        self.mk_app(force=True)

    def get_file(self,job_id,fname,as_file=None):

        if isinstance(job_id, RemoteJob):
            job_id = job_id.job_id

        if verbose:
            if as_file is not None:
                print(colored("Getting file:","green"), fname,colored("as:","green"),as_file)
            else:
                print(colored("Getting file:","green"), fname)
        headers = self.get_headers()
        pause()
        # Prevent double slashes
        fname = re.sub(r'^/','',fname)
        if self.is_ssh():
            # zzz
            self.scp_cmd([self.get_machine()+":/"+fname,as_file]) 
            with open(as_file,"r") as fd:
              return fd.read()
        response = requests.get(self.fill("{apiurl}/jobs/v2/")+job_id+"/outputs/media/"+fname, headers=headers)
        check(response)
        content = response.content
        is_binary = False
        for header in response.headers:
            if header.lower() == "content-type":
                if response.headers[header].lower() == "application/octet-stream":
                    is_binary = True
        if as_file is not None:
            if is_binary:
                fd = os.open(as_file,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o0644)
                os.write(fd,content)
                os.close(fd)
            else:
                with open(as_file,"w") as fd:
                    print(content,file=fd)
        return content

    def job_file_list(self,jobid,dir='',recurse=False):
        if dir == "" and verbose:
            print(colored("Output for job: "+jobid,"magenta"))

        if self.is_ssh():
            exec_txt = os.path.join(self.jetlag_dir(), "execution.txt")
            job = None
            for j in self.get_meta('%'):
                if j["value"]["jobid"] == jobid:
                    job = j
                    break
            with open(exec_txt,"r") as fd:
                exec_data = json.loads(fd.read())
            job_dir = os.path.join(exec_data["workDir"], job["name"][len("jobdata-"):])
            out, err, rc = self.ssh_cmd(["find",job_dir])
            li = out.strip().split('\n')
            for line in li:
                print(colored("file:","blue"),line)
            return li
        headers = self.get_headers()
        params = ( ('limit', '100'), ('offset', '0'),)
        pause()
        response = requests.get(self.fill("{apiurl}/jobs/v2/")+jobid+"/outputs/listings/"+dir, headers=headers, params=params)
        check(response)
        jdata = response.json()["result"]
        outs = []
        for fdata in jdata:
            fname = fdata["path"]
            if verbose:
                print(colored("File:","blue"),fname)
            if fdata["format"] == "folder":
                if recurse:
                    outs += self.job_file_list(jobid,fname,verbose)
                continue
            else:
                outs += [fname]
            if dir != '':
                continue
        return outs

    def job_stop(self, jobid):
        data = json.dumps({ "action": "stop" })
        headers = self.get_headers(data)
        pause()
        response = requests.post(self.fill("{apiurl}/jobs/v2/")+jobid, headers=headers, data=data)
        check(response)
        return response.json()

    def access(self, user, allow):
        # Need to grant access to the meta data, the app, the exec machine, and the storage machine
        if allow:
            role = 'USER'
            apps_pems = 'READ_EXECUTE'
            meta_pems = 'READ'
        else:
            role = 'NONE'
            apps_pems = 'NONE'
            meta_pems = 'NONE'
        self.system_role('{execm_id}',user,role)
        self.system_role('{forkm_id}',user,role)
        self.system_role('{storage_id}',user,role)
        self.apps_pems('{app_name}-{app_version}',user,apps_pems)
        self.apps_pems('{fork_app_name}-{app_version}',user,apps_pems)
        if allow:
            print(self.fill("Access to {app_name} "+colored("granted","green")+" to user "+user))
        else:
            print(self.fill("Access to {app_name} "+colored("revoked","red")+" from user "+user))

    def system_role(self, system, user, role):
        data = json.dumps({"role":role})
        headers = self.get_headers(data)
        
        url = self.fill('{apiurl}/systems/v2/'+system+'/roles/'+user)
        response = requests.post(url, headers=headers, data=data)
        check(response)
        if verbose:
            print(colored("System Role:","green"),user,colored("of","green"),system,colored("=>","green"),role)
            self.show(response)

    def show(self, r):
        if hasattr(r,"json"):
            jdata = r.json()
            if "result" in jdata and type(jdata["result"]) == dict:
                jdata = jdata["result"]
            jdata = link_filter(jdata)
            pp.pprint(jdata)
        else:
            print(r)

    def apps_pems(self, app, user, pem):
        data = json.dumps({'permission': pem})
        headers = self.get_headers(data)

        url=self.fill('{apiurl}/apps/v2/'+app+'/pems/'+user)
        response = requests.post(url, headers=headers, data=data)
        check(response)
        if verbose:
            print(colored("Apps Pems:","green"),user,colored("of","green"),app,colored("=>","green"),pem)
            self.show(response)

    def job_history(self, job_id):
        headers = self.get_headers()
        pause()
        response = requests.get(self.fill("{apiurl}/jobs/v2/")+job_id+'/history/', headers=headers)
        if response.status_code == 404:
            return None
        check(response)
        jdata = response.json()["result"]
        return jdata

    def jetlag_dir(self):
        assert self.is_ssh()
        jdir = os.path.join(home, ".sshcfg", "jetlag", self.jetlag_id)
        os.makedirs(jdir, exist_ok=True)
        return jdir

    def store_data(self, data, fname):
        data = rm_auth(data)
        data_file = os.path.join(self.jetlag_dir(),fname)
        with open(data_file, "w") as fd:
            fd.write(json.dumps(data))
        data_dir = os.path.join(home,".sshcfg","id",data["id"])
        os.makedirs(data_dir,exist_ok=True)
        data_file = os.path.join(data_dir, fname)
        with open(data_file, "w") as fd:
            fd.write(json.dumps(data))

    def is_ssh(self):
        return self.agave_auth.utype == "ssh"

    def get_machine(self):
        return self.agave_auth.user + "@" + self.agave_auth.baseurl

    def remote_cmd(self, c0, cmd):
        auth_file = self.agave_auth.get_auth_file()
        key_file = os.path.join(os.path.dirname(auth_file),"id_rsa")
        pcmd = [c0,"-o","PasswordAuthentication=no","-i",key_file]+cmd
        p = Popen(pcmd,stdout=PIPE,stderr=PIPE,universal_newlines=True)
        out, err = p.communicate()
        if verbose:
            if out.strip() != "":
                print(out)
            if err.strip() != "":
                print(colored(err,"red"))
        return out,err,p.returncode
    
    def ssh_cmd_thread(self,cmd):
        return run_task(self.ssh_cmd, (cmd,))
        
    def ssh_cmd(self, cmd):
        return self.remote_cmd("ssh", [self.get_machine()] + cmd)
    
    def scp_cmd(self, cmd):
        return self.remote_cmd("scp", cmd)

    def job_list(self, num):
        headers = self.get_headers()
        params = (
            ('limit',num),
        )
        pause()
        if self.is_ssh():
            print("Job list by ssh",self.auth.keys())
            o,e,r = self.ssh_cmd(["squeue"])
            assert r == 0
            return {}
        response = requests.get(self.fill("{apiurl}/jobs/v2/"), headers=headers, params=params)
        check(response)
        jdata = response.json()["result"]
        return jdata

    def get_app_pems(self,app='queue'):
        headers = self.get_headers()
        if app == 'fork':
            app_name = self.fork_app_name
        else:
            app_name = self.app_name
        version = self.app_version
        url = self.fill("{apiurl}/apps/v2/"+app_name+"-"+version+"/pems")
        response = requests.get(url, headers=headers)
        if response.status_code == 403:
            print("error for url:",url)
        check(response)
        jdata = response.json()
        return link_filter(jdata["result"]) 

    # End class JetLag

def clone_machine(auth, name, user, home_dir=None, root_dir=None, work_dir=None, scratch_dir=None, allocation=None):
    def extract_str(arg):
        if type(arg) in [tuple, list] and len(arg) == 1:
            return extract_str(arg[0])
        elif type(arg) == str:
            return arg
        raise Exception("bad type:"+str(arg))
    jlag = JetLag(auth)
    sysx = jlag.get_system(name)
    assert sysx is not None, f"Invalid name {name}"
    #pp.pprint(sysx)

    if root_dir is None:
        root_dir = sysx["storage"]["rootDir"]
    if root_dir is None:
        root_dir = "/home/"+user+"/root"

    if home_dir is None:
        home_dir = sysx["storage"]["homeDir"]
    if home_dir is None:
        home_dir = os.path.join(root_dir,"home")

    if work_dir is None:
        work_dir = sysx["workDir"]
    if work_dir is None:
        work_dir = home_dir

    if scratch_dir is None:
        scratch_dir = sysx["scratchDir"]
    if scratch_dir is None:
        scratch_dir = work_dir

    spec = {
        "machine_user":user,
        "machine":re.sub(r'\..*','',sysx["login"]["host"]),
        "domain":re.sub(r'^[^\.]+\.','',sysx["login"]["host"]),
        "port":sysx["login"]["port"],
        "queue":sysx["queues"][0]["name"],
        "max_nodes":sysx["queues"][0]["maxNodes"],
        "max_run_time":sysx["queues"][0]["maxRequestedTime"],
        "max_procs_per_node":sysx["queues"][0]["maxProcessorsPerNode"],
        "min_procs_per_node":1,
        "max_jobs_per_user":sysx["maxSystemJobsPerUser"],
        "max_jobs":sysx["maxSystemJobs"],
        "scheduler":sysx["scheduler"],
        "custom_directives":sysx["queues"][0]["customDirectives"],
    
        "scratch_dir":scratch_dir,
        "work_dir":work_dir,
        "home_dir":home_dir,
        "root_dir":root_dir
    }
    if allocation is not None:
        spec["allocation"] = allocation
    #if verbose:
    #    pp.pprint(spec)
    return spec #JetLag(auth, **spec)

class FileLink:
    def __init__(self, link):
        self.link = link

class FileContents:
    def __init__(self, contents):
        self.contents = contents

def mk_input(input_tgz):
    """
    Generate a tarball from a hash of file names/contents.
    """
    pcmd(["rm","-fr","run_dir"])
    os.mkdir("run_dir")
    for k in input_tgz.keys():
        val = input_tgz[k]
        t = type(val)
        fname = os.path.join("run_dir",k)
        if t == FileLink:
            s = os.stat(val.link)
            if s.st_size < FILE_LINK_SIZE:
                pcmd(["cp",val.link,fname])
            else:
                fname += ".link"
                with open(fname,"w") as fd:
                    print(val.link,file=fd)
        elif t == FileContents:
            with open(fname,"w") as fd:
                print(val.contents,file=fd)
        elif t == str:
            with open(fname,"w") as fd:
                print(input_tgz[k].strip(),file=fd)
        else:
            raise Exception("Bad value to dict input_tgz")
    pcmd(["tar","czf","input.tgz","run_dir"])

class RemoteJob:
    def __repr__(self):
        if self.job_id is not None:
            return "RemoteJob(id='%s',user='%s',machine='%s.%s')" % (
                self.job_id, self.jlag.owner, self.jlag.machine, self.jlag.domain)
        else:
            return "RemoteJob(name='%s',user='%s',machine='%s.%s)" % (
                self.job_name, self.jlag.owner, self.jlag.machine, self.jlag.domain)

    def __init__(self, jlag, job_id=None, job_name=None):
        self.jlag = jlag
        self.job_id = job_id
        self.job_name = job_name
        assert job_id is not None or job_name is not None
        assert job_id is None or type(job_id) == str
        self.last_status = "EMPTY"
        self.jdata = None

    def wait(self):
        s = None
        while True:
            self.jlag.poll()
            n = self.status()
            if n != s:
                c = get_status_color(n)
                print(colored(n,c))
                s = n
            sleep(poll_time)
            if n in job_done:
                return

    def full_status(self):
        return self.jlag.job_status(self.job_id)

    def status(self):
        if self.last_status in job_done:
            return self.last_status
        self.jdata = self.full_status()
        self.last_status = self.jdata["status"]
        return self.last_status

    def get_result(self, force=True):
        if hasattr(self,"result"):
            return self.result
        if self.status() == "FINISHED":
            jobdir="jobdata-"+self.job_id
            if not os.path.exists(jobdir):
                os.makedirs(jobdir, exist_ok=True)
            if not os.path.exists(os.path.join(jobdir,"output.tgz")):
                try:
                    self.jlag.get_file(self.job_id,"output.tgz",jobdir+"/output.tgz")
                    pcmd(["tar","xf","output.tgz"],cwd=jobdir)
                    if self.jdata is None:
                        self.status(self.job_id)
                except:
                    if verbose:
                        print(colored("Could not get output.tgz","red"))
            out_file = os.path.join(jobdir,"job.out")
            err_file = os.path.join(jobdir,"job.err")
            outs = self.jlag.job_file_list(self.job_id,recurse=False)
            for out in outs:
                g = re.match(r'.*(?:\.(out|err))$',out)
                if g:
                    tmp_file = os.path.join(jobdir, "job.%s" % g.group(1))
                    if not os.path.exists(tmp_file):
                        self.jlag.get_file(self.job_id, out, tmp_file)
            # Did the job create a result file that was consumable by Python?
            if os.path.exists(os.path.join(jobdir,'run_dir','result.py')):
                with open(os.path.join(jobdir,'run_dir','result.py'),"r") as fd:
                    val = fd.read().strip()
                    try:
                        self.result = eval(val)
                    except TypeError as se:
                        # This is triggered by incorrectly generated
                        # Phylanx output.
                        self.result = eval(re.sub(r'^list','',val))
            else:
              self.result = None
            return self.result
        return None

    def std_output(self):
        out_file = os.path.join("jobdata-"+self.job_id,"job.out")
        if not os.path.exists(out_file):
            self.get_result()
        try:
            with open(out_file, "r") as fd:
                return fd.read()
        except FileNotFoundError as fnf:
            return ""

    def err_output(self):
        out_file = os.path.join("jobdata-"+self.job_id,"job.err")
        if not os.path.exists(out_file):
            self.get_result()
        try:
            with open(out_file, "r") as fd:
                return fd.read()
        except FileNotFoundError as fnf:
            return ""

    def stop(self):
        self.jlag.job_stop(self.job_id)

    def diag(self):
        jl = self.jlag
        job_id = self.job_id
        status = jl.job_status(job_id)
        ret = {}
        if status is None:
            print(colored("No such job:","red"),job_id)
            exit(2)
        if "lastStatusMessage" in status:
            if verbose:
                print(colored("Last Status:","green"),status["lastStatusMessage"])
            ret["lastStatusMessage"] = status["lastStatusMessage"]
        n = 0
        last_secs = None
        history = jl.job_history(job_id)
        ret["history"] = history
        for item in history:
            n += 1
            status = item["status"]
            color = get_status_color(status)
            if verbose:
                print(n,colored(status, color))
            dt, secs = from_agave_time(item["created"])
            if last_secs is None:
                last_secs = secs
            else:
                if verbose:
                    print(" ",dt," ",colored(ago(last_secs - secs),"yellow"))
            if verbose:
                print(" ",item["description"])

        return ret

class Action:

    def __init__(self, auth):
        self.auth = auth

    def make_dir(self,jetlag_id,dirname):
        jl = JetLag(self.auth,jetlag_id=jetlag_id)
        jl.make_dir(dirname)

    def hello_world(self,jetlag_id,jtype="fork"):
        jl = JetLag(self.auth, jetlag_id=jetlag_id)
        job = jl.hello_world_job(jtype=jtype)
        job.wait()
        err = job.err_output()
        assert re.search(r'(?m)^This is stderr', err), err
        out = job.std_output()
        assert re.search(r'(?m)^This is stdout', out), out
        print("hello_world() test passed")

    def system_info(self,system_name):
        jl = JetLag(self.auth)
        pp.pprint(jl.get_system(system_name))

    def get_job_files(self,job_id):
        jl = JetLag(self.auth)
        job = RemoteJob(jl, job_id)
        job.get_result()

    def get_job_file(self,job_id,fname,as_file=None):
        jl = JetLag(self.auth)
        if as_file is None:
            c = jl.get_file(job_id, fname)
            try:
                print(c.decode())
            except:
                print(c)
        else:
            jl.get_file(job_id, fname, as_file)

    def job_diag(self,job_id):
        jl = JetLag(self.auth)
        job = RemoteJob(jl, job_id)
        job.diag()

    def job_list(self,num):
        jl = JetLag(self.auth)
        records = []
        for job in jl.job_list(num):
            status = job["status"]
            #color = get_status_color(status)
            cr = job["created"]
            dt, secs = from_agave_time(cr)
            records += [(job["id"],status,dt,secs,cr)]
            #print(job["id"],": ",colored(status,color)," ",dt," ",colored(ago(secs),"yellow"),sep='')
        records = sorted(records, key=lambda x:x[3])
        for record in records:
            status = record[1]
            color = get_status_color(status)
            dt = record[2]
            secs = record[3]
            print(record[0],": ",colored(status,color)," ",dt," ",colored(ago(secs),"yellow"),sep='')

    def access(self,jetlag_id,user,boolean):
        assert boolean in ["True", "False"]
        jl = JetLag(self.auth, jetlag_id=jetlag_id)
        jl.access(user,boolean == "True")

    def get_app_pems(self,jetlag_id):
        jl = JetLag(self.auth, jetlag_id=jetlag_id)
        pp.pprint(jl.get_app_pems())

    def get_meta(self,name):
        jl = JetLag(self.auth)
        #jl.del_meta(name)
        print(jl.get_meta(name))

    def set_meta(self,name,value):
        jl = JetLag(self.auth)
        #jl.del_meta(name)
        print(jl.set_meta({"name":name,"value":value}))

    def del_meta(self,name):
        jl = JetLag(self.auth)
        m = jl.get_meta(name)
        for k in m:
            print(k,jl.del_meta(k))

    def mkdir(self,jetlag_id,dir_name):
        if self.is_ssh():
            o,e,r = self.ssh_cmd(["mkdir","-p",dir_name])
        jl = JetLag(self.auth, jetlag_id=jetlag_id)
        jl.make_dir(dir_name)

    def upload(self,jetlag_id,local,remote):
        jl = JetLag(self.auth, jetlag_id=jetlag_id)
        with open(local, "r") as fd:
            jl.file_upload(os.path.dirname(remote), os.path.basename(remote), fd.read())

    def system_list(self):
        jl = JetLag(self.auth)
        n = 0
        for system in jl.systems_list():
            n += 1
            if n % 4 == 0:
                print(colored(system["id"],"green"))
            else:
                print(system["id"])

    def cloneable_list(self):
        global verbose
        jl = JetLag(self.auth)
        n = 0
        for system in jl.systems_list():
            try:
                vsave = verbose
                verbose = False
                clone_machine(self.auth, name=system["id"], user='xxx') 
                n += 1
                if (n % 3) == 0:
                    print(colored(system["id"],"yellow"))
                else:
                    print(system["id"])
            except:
                pass
            finally:
                verbose = vsave

    def jetlag_ids(self):
        """Provides a list of the defined jetlag ids"""
        jl = JetLag(self.auth)
        for jid in jl.jetlag_ids():
            print(jid)

    def job_output(self, job_id):
        jl = JetLag(self.auth)
        job = RemoteJob(jl, job_id)
        print(job.std_output())
        print(job.err_output())

    def job_file_list(self,job_id):
        jl = JetLag(self.auth)
        jl.job_file_list(job_id)

    def system_edit(self,name):
        """Creates a file to edit a system"""
        f = JetLag.__init__
        code = f.__code__
        narg = code.co_argcount
        args = code.co_varnames
        g = re.match(r'^(\w+)-(\w+)', name)
        if g:
            machine_user = g.group(2)
        else:
            machine_user = self.auth.user
        if name.lower().strip() == "none":
            spec = {}
        else:
            spec = clone_machine(self.auth, name=name, user=machine_user)
        assert not os.path.exists("tmp.py"), "File tmp.py exists. Please delete it or move it out of the way."
        with open("tmp.py", "w") as fd:
            print("from jetlag import JetLag, Auth, set_verbose",file=fd)
            print("set_verbose(True)",file=fd)
            print("auth = Auth('%s','%s',baseurl='%s',tenant='%s')" % (self.auth.utype, self.auth.user, self.auth.baseurl, self.auth.tenant),file=fd)
            print("auth.create_or_refresh_token()",file=fd)
            print("jlag = JetLag(auth,",file=fd)
            for i in range(2,narg):
                d = f.__defaults__[i-2]
                name = args[i]
                if name in spec:
                    d = spec[name]
                if i + 1 < narg:
                    e = ','
                else:
                    e = ')'
                if type(d) == str:
                    print("    ",args[i],"='",d,"'",e,sep='',file=fd)
                else:
                    print("    ",args[i],"=",d,e,sep='',file=fd)
            print("jlag.configure()",file=fd)
            print('job = jlag.hello_world_job(jtype="queue")',file=fd)
            print('job.wait()',file=fd)
            print('err = job.err_output()',file=fd)
            print('import re',file=fd)
            print('assert re.search(r"(?m)^This is stderr", err), err',file=fd)
            print('out = job.std_output()',file=fd)
            print('assert re.search(r"(?m)^This is stdout", out), out',file=fd)
            print('print("hello_world() test passed")',file=fd)
            print("File 'tmp.py' created. Edit and run to configure or reconfigure.")


def usage()->None:
    print("Usage: jetlag.py [--ssl-verify=(yes|no)] session action")
    print("Usage: jetlag.py session-list")
    print("Usage: jetlag.py session-create (tapis|agave) user [baseurl tenant]")
    print("Usage: jetlag.py session-create ssh user@host") 
    print("   'session': A substring which is contained exactly one session id.")
    print(" Actions:")
    for a in dir(Action):
        if re.match(r'^__.*__$', a):
            pass
        else:
            f = getattr(Action, a)
            if type(f) == type(Action.access):
                code = f.__code__
                narg = code.co_argcount
                args = code.co_varnames
                print("   Action:",a,args[1:narg])
                if hasattr(f, "__doc__"):
                    d = getattr(f, "__doc__")
                    if d is not None:
                        if "Create a new string object from the given object" not in d:
                            print("     ",colored(d,"yellow"))
    raise Exception()

if __name__ == "__main__":
    home = os.environ["HOME"]
    for arg in sys.argv:
        g = re.match(r'--(verify-ssl)=(.*)', arg)
        if g:
            k, v = g.group(1), g.group(2)
            if k == "verify-ssl":
                requests.set_ssl(v.strip().lower() not in ["no", "false"])
        else:
            cmd_args += [arg]
    if len(cmd_args)==2 and cmd_args[1] in ["sessions","session-list","session_list"]:
        n = 0
        for session in get_auth_sessions():
            a = get_auth_by_fname(session)
            idstr_ = a.get_idstr()
            auth_file = a.get_auth_file()
            n += 1
            if n == 3:
                print(colored(idstr_,"cyan"))
                print(colored("  file:","blue"),colored(auth_file,"green"))
            else:
                print(idstr_)
                print(colored("  file:","blue"),colored(auth_file,"yellow"))
        exit(0)
    if len(cmd_args) > 1 and cmd_args[1] in ["session-create","session_create"]:
        if len(cmd_args) not in [4,6]:
            usage()
        utype = cmd_args[2]
        uname = cmd_args[3]
        print(colored("utype:","green"),utype)

        # Direct ssh type of session
        if utype == "ssh":
            user, host = uname.split('@')
            ssh_data = get_ssh_data()
            if host in ssh_data:
                if "hostname" in ssh_data:
                    host = ssh_data[host]["hostname"]
            set_ssh_persist(host)
            print(colored("ssh:","green"),user,host)
            a = Auth(utype, user, baseurl=host, tenant="ssh")
            auth_file = a.get_auth_file()
            auth_dir = os.path.dirname(auth_file)
            os.makedirs(auth_dir,exist_ok=True)
            if os.path.exists(auth_file):
                with open(auth_file,"r") as fd:
                    try:
                        jdata = json.loads(fd.read())
                    except:
                        pass
            else:
                jdata = {}
            jdata["username"] = user
            jdata["baseurl"] = host
            jdata["tenantid"] = "ssh"
            jdata["access_token"] = rand_name()
            jdata["refresh_token"] = rand_name()
            with open(auth_file,"w") as fd:
                print(json.dumps(jdata),end='',file=fd)

        if a is None:
            if len(cmd_args)!=4:
                baseurl = cmd_args[4]
                if not re.match(r'^https://', baseurl):
                    baseurl = "https://"+baseurl
                tenant = cmd_args[5]
                print(colored("baseurl:","green"), baseurl)
                print(colored("tenant:","green"), tenant)
                jdata = json.loads(requests.get(baseurl+"/tenants/").content.decode())
                tenant_is_good = False
                tnames = []
                for jresult in jdata["result"]:
                    tname = jresult["code"]
                    tnames += [tname]
                tnames_str = "', '".join(tnames)
                assert tenant in tnames, f"Invalid tenant: '{tenant}'. Valid names are: '{tnames_str}'"
                a = Auth(utype, uname, baseurl=baseurl, tenant=tenant)
            else:
                a = Auth(utype, uname)
        print(colored("auth file","green"),a.get_auth_file())
        a.create_or_refresh_token()
        exit(0)
    if len(cmd_args) < 2:
        print("Too few args")
        usage()
    #cmd_args = cmd_args[:2]+[""]+cmd_args[2:]
    #if len(cmd_args) < 4:
        #usage()
    set_verbose(True)
    auth = get_auth_by_session(cmd_args[1]) 
    auth.create_or_refresh_token()
    assert auth.is_valid
    if len(cmd_args) <= 2:
        usage()
    action_name = re.sub(r'-','_',cmd_args[2])
    action = Action(auth)
    if hasattr(action, action_name):
        method = getattr(action, action_name)
    else:
        method = None
    if hasattr(method, "__call__"):
        method(*cmd_args[3:])
    else:
        print("Attempted action was:",action_name)
        print("Valid actions are:")
        s : str
        for s in dir(action):
            item = getattr(action, s)
            if not re.match(r'^__', s) and hasattr(item, "__call__"):
                print(" ",s)
        print("Not a valid action: '%s'" % re.sub(r'_','-',action_name))
        usage()
