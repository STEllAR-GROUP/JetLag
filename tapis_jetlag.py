import os, sys, re, json
import diagrequests as requests
from colored import colored
from jetlag import *
from abc import ABCMeta, abstractmethod
from typing import List, Tuple, Any, Union, Dict, Optional, cast, TypedDict, Final
from requests.models import Response
from time import time
from datetime import datetime
from copy import copy, deepcopy
from math import log, ceil

##################### UTILS #######################

# Agave/Tapis uses all of these http status codes
# to indicate succes.
success_codes = [200, 201, 202]

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

def from_agave_time(ts : str)->Tuple[datetime,float]:
    from time import mktime, time
    from datetime import datetime
    import re
    # To install: pip install python-dateutil
    from dateutil import tz

    # Is the time string for UTC time?
    is_utc_time : bool = ts[-1] == 'Z'

    # Search for fractions of a second
    g = re.search(r'\.\d+',ts)
    if g:
        s = ts[:g.start()]
        frac = float(g.group(0))
    else:
        s = re.sub(r'Z$','',ts)
        frac = 0

    # The Z timezone
    that_tz = tz.gettz("GMT") 

    # The local timezone
    this_tz = tz.tzlocal()

    # Parse the date and time into val
    val = datetime.strptime(s,"%Y-%m-%dT%H:%M:%S")

    # If necessary, convert the timezone
    if is_utc_time:
        val = val.replace(tzinfo=that_tz)
        val = val.astimezone(this_tz)

    return (val, val.timestamp() + frac)

##################### JETLAG #######################

def find_tapis_auth_clients(user:str)->List[str]:
    result : List[str] = []
    root = os.path.join(home,".tapis",user)
    try:
        for p in os.listdir(root):
            pf = os.path.join(root, p)
            for q in os.listdir(pf):
                if q == "current":
                    qf = os.path.join(pf,q)
                    with open(qf, "r") as fd:
                        jdata = json.loads(fd.read().strip())
                    assert type(jdata) == dict
                    if "client" in jdata:
                        result += [jdata["client"]]
    except FileNotFoundError as fnf:
        pass
    return result

class TapisAuth(AuthBase):
    """
    The Universal (i.e. Tapis or Agave) authorization
    """
    def __init__(self, user:str, client:ostr=None, password:ostr=None, baseurl:ostr=None, tenant:ostr=None, create_client:bool=False)->None:
        if client is None:
            clients = find_tapis_auth_clients(user)
            raise ClientException(clients)
                
        self.client : str = client
        self.is_valid = False
        if user is not None:
            assert '@' not in user

        # Fill in the default baseurl
        if baseurl is None:
            baseurl = "https://api.tacc.utexas.edu"
        
        # Fill in the default tenant
        if tenant is None:
            tenant = "tacc.prod"

        self.user = user
        self.baseurl = baseurl
        self.tenant = tenant
        self.password = password
        self.auth_data : JDict

        self.auth_age : float = -1e9

        auth_file = self.get_auth_file()
        if not os.path.exists(auth_file):
            assert create_client, f"The client '{client}' does not exist. Please call TapisAuth() with create_client=True."
            self.create_token()
        self.get_auth_data()

    def __repr__(self)->str:
        return self.get_idstr()

    def get_idstr(self)->str:
        idstr = "tapis:"+self.user+":"+re.sub(r'^https://','',self.baseurl)+":"+self.tenant
        if self.client is not None:
            idstr += ":"+self.client
        return idstr

    def get_auth_file(self)->str:
        burl = codeme("~".join([
            self.tenant,
            self.baseurl,
            self.user,
            self.client,
        ]))
        return os.path.join(home, ".tapis", self.user, burl, "current")

    def create_or_refresh_token(self)->None:
        auth_file = self.get_auth_file()
        if get_verbose():
            print(colored("Auth file:","green"), auth_file)
        if os.path.exists(auth_file):
            self.auth_mtime = os.path.getmtime(auth_file)
        if not self.refresh_token():
            self.create_token()

    def get_password(self)->str:
        assert self.password is not None
        return self.password

    def create_token(self)->Optional[JType]:

        auth = (
            self.user,
            self.get_password()
        )

        # Create a client name and search to see if it exists
        client_name = self.client #rand_name() #"client-"+idstr()

        # Delete the client if it exists
        url = self.baseurl+'/clients/v2/'+client_name
        response = requests.delete(url, auth=auth)

        data = {
            'clientName': client_name,
            'tier': 'Unlimited',
            'description': '',
            'callbackUrl': ''
        }

        url = self.baseurl+'/clients/v2/'
        response = requests.post(url, data=data, auth=auth)
        check(response)
        jdata = response.json()
        jdata = cast(JDict,jdata["result"])
        assert type(jdata)==dict
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
        expires_in = jdata["expires_in"]
        if type(expires_in) == int:
            delt = expires_in
        elif type(expires_in) == str:
            delt = int(expires_in)
        else:
            assert False
        ts = now + delt

        verify_ssl : bool = requests.verify_ssl

        fdata = cast(JDict,{
            "verify_ssl":verify_ssl,
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
        })
        self.auth_data = fdata
        self.save_auth_data()
        self.is_valid = True
        return fdata


    def refresh_token(self)->bool:
        """
        This is under construction (i.e. it doesn't work).
        In principle, it can refresh an agave/tapis token.
        """
        auth_file = self.get_auth_file()
        if self.auth_data is None:
            self.get_auth_data()
            if self.auth_data is not None and "verify_ssl" in self.auth_data:
                if not self.auth_data["verify_ssl"]:
                    if get_verbose(): 
                        requests.set_ssl(False)
        if not os.path.exists(auth_file):
            return False 
        if age(auth_file) < 30*60:
            self.is_valid = True
            return True

        auth_data = self.get_auth_data()

        # Check that the data in the file
        # is compatible.
        auth_user : str = str(auth_data["username"])
        assert auth_user == self.user, \
            "Incorrect user in auth file '%s' != '%s'" % (auth_user,self.user)

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
            if get_verbose():
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

    def save_auth_data(self)->None:
        auth_file = self.get_auth_file()
        os.makedirs(os.path.dirname(auth_file), exist_ok=True)

        # Ensure the auth_file exists
        if not os.path.exists(auth_file):
            with open(auth_file,"w"):
                pass

        # Ensure the auth_file permissions
        os.chmod(auth_file, 0o600)

        # Save the verify_ssl state
        assert self.auth_data is not None
        if "verify_ssl" not in self.auth_data:
            self.auth_data["verify_ssl"] = requests.verify_ssl

        # Actually write the auth file
        with open(auth_file,"w") as fd:
            fd.write(json.dumps(self.auth_data))

    def get_auth_data(self)->JDict:
        auth_file = self.get_auth_file()
        auth_age = os.path.getmtime(auth_file)
        if auth_age == self.auth_age:
            return self.auth_data
        self.auth_age = auth_age
        auth_data : JDict
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

    def get_headers(self,data:ostr=None)->Dict[str,str]:
        """
        We need basically the same auth headers for
        everything we do. Factor out their initialization
        to a common place.
        """
        self.refresh_token()
        access_token = self.get_auth_data()["access_token"]
        headers = {
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Authorization': f'Bearer {access_token}',
            'Connection': 'keep-alive',
            'User-Agent': 'python-requests/2.22.0',
        }
        if data is not None:
            assert type(data) == str
            headers['Content-Type'] = 'application/json'
            headers['Content-Length'] = str(len(data))
        return headers

    def get_system(self,name:str)->Optional[Machine]:
        if verbose:
            print(colored("System:","green"),name)
        headers = self.get_headers()
        response = requests.get(
            f'{self.baseurl}/systems/v2/{name}', headers=headers)
        if response.status_code == 404:
            return None
        check(response)
        json_data = response.json()
        json_data = json_data["result"]
        g = re.match(r'(\w+)-(\w+)-exec-(\w+)-(.*)', name)
        assert g is not None
        full_name = json_data["storage"]["host"]
        g2 = re.match(r'(.*?)\.(.*)', full_name)
        assert g2 is not None
        queue = json_data["queues"][0]
        return Machine(
            definition_owner=g[3],
            name=g2[1],
            user=g[2],
            domain=g2[2],
            queue=queue["name"],
            home_dir=json_data["storage"]["homeDir"],
            port=json_data["storage"]["port"],
            max_jobs_per_user=json_data["maxSystemJobsPerUser"],
            max_jobs=queue["maxJobs"],
            max_nodes=queue["maxNodes"],
            scratch_dir=json_data["scratchDir"],
            work_dir=json_data["workDir"],
            root_dir=json_data["storage"]["rootDir"],
            max_run_time="01:00:00",
            max_procs_per_node=queue["maxProcessorsPerNode"],
            scheduler=json_data["scheduler"],
            custom_directives=queue.get("custom_directives",None),
            suffix = g[4])

    def systems_list(self)->List[Machine]:
        headers = self.get_headers()
        response = requests.get(f"{self.baseurl}/systems/v2/", headers=headers)
        check(response)
        jdata = response.json()["result"]
        result = []
        assert type(jdata) == list
        for jd in jdata:
            idstr = cast(str,jd["id"])
            typ   = cast(str,jd["type"])
            if typ == "EXECUTION" and re.match(r'^\w+-\w+-exec-\w+-\w+', idstr):
                m = self.get_system(idstr)
                if m is not None:
                    result += [m]
        return result

class TapisJetlag(JetlagBase):
    def __init__(self, auth:TapisAuth, machine:Machine)->None:
        JetlagBase.__init__(self, auth, machine)
        self.storage_id = f'{self.machine.name}-{self.machine.user}-storage-{self.machine.definition_owner}-{self.machine.suffix}'
        self.execm_id = f'{self.machine.name}-{self.machine.user}-exec-{self.machine.definition_owner}-{self.machine.suffix}'
        self.forkm_id = f'{self.machine.name}-{self.machine.user}-fork-{self.machine.definition_owner}-{self.machine.suffix}'
        self.app_name = f'{self.machine.name}-{self.machine.user}_queue_{self.machine.definition_owner}-{self.machine.suffix}'
        self.fork_app_name = f'{self.machine.name}-{self.machine.user}_fork_{self.machine.definition_owner}-{self.machine.suffix}'
        self.app_version = "1.0.0"
        self.app_id = f'{self.app_name}-{self.app_version}'
        self.fork_app_id = f'{self.fork_app_name}-{self.app_version}'
        self.baseurl = auth.baseurl
        self.deployment_path = "new-tapis-deployment"
        self.jobs_dir = f'tjob/{auth.user}'
        self.jetlag_id = f"{self.machine.name}-{self.machine.user}-{self.machine.definition_owner}"

        key_dir = os.path.dirname(self.auth.get_auth_file())
        priv_key = os.path.join(key_dir, "id_rsa")
        if get_verbose():
            print(colored("Using key:","green"),priv_key)

        pub_key = priv_key + '.pub'
        if not os.path.exists(priv_key):
            os.makedirs(key_dir,exist_ok=True)
            if get_verbose():
                print(colored("Creating key:","green"),priv_key)
            r, o, e = pcmd(["ssh-keygen","-m","PEM","-t","rsa","-f",priv_key,"-P",""])

        assert os.path.exists(pub_key)
        with open(pub_key, "r") as fd:
            pub_key_text = fd.read().strip()
        assert os.path.exists(priv_key)
        with open(priv_key, "r") as fd:
            priv_key_text = fd.read().strip()
        if get_verbose():
            print(colored("pub key:","cyan"),pub_key)
            print(colored(pub_key_text,"yellow"))

        self.machine_auth : JDict = {
            "username" : self.machine.user,
            "publicKey" : pub_key_text,
            "privateKey" : priv_key_text,
            "type" : "SSHKEYS"
        }

    def get_headers(self,data:ostr=None)->Dict[str,str]:
        return cast(TapisAuth,self.auth).get_headers(data)

    def mk_storage(self,force:bool=False)->None:
        storage_id = self.storage_id
        if get_verbose():
            print(colored("Creating Storage Machine:","green"),storage_id)
        port = self.machine.port
        machine = self.machine
        storage : JDict = {
            "id" : storage_id,
            "name" : f"{machine.name} storage ({machine.user})",
            "description" : "The {machine} computer",
            "site" : "{domain}",
            "type" : "STORAGE",
            "storage" : {
                "host" : f"{machine.name}.{machine.domain}",
                "port" : port,
                "protocol" : "SFTP",
                "rootDir" : f"{machine.root_dir}",
                "homeDir" : f"{machine.home_dir}",
                "auth" : self.machine_auth,
                "publicAppsDir" : f"{machine.home_dir}/apps"
            }
        }
        if not force:
            headers = self.get_headers()
            apiurl = self.auth.get_auth_data()['baseurl']
            response = requests.get(
                f'{apiurl}/systems/v2/{self.storage_id}', headers=headers)
            # This system is already defined.
            if response.status_code in success_codes:
                return

        if (force or not self.check_machine(storage_id)):
            json_storage : str = json.dumps(storage)
            headers = self.get_headers(json_storage)
            response = requests.post(
                f'{self.baseurl}/systems/v2/', headers=headers, data=json_storage)
            check(response)
            assert self.check_machine(storage_id)

    def check_machine(self,machine:str)->bool:
        """
        Checks that we can do a files list on the machine.
        This proves (or disproves) that we have auth working.
        """
        if get_verbose():
            print(colored("Checking we can list files from machine:","green"),machine)
        headers = self.get_headers()
        params = (('limit','5'),('offset','0'),)
        url = f'{self.baseurl}/files/v2/listings/system/{machine}/'
        pause()
        response = requests.get(url, headers=headers, params=params)
        #if response.status_code == 404:
        #    if get_verbose():
        #        print(colored("Received 404 from URL","red"),url)
        #    return False
        check(response)
        file_data = response.json()["result"]
        n = 0
        for file in file_data:
            if get_verbose():
                print(colored("File:","blue"),file["name"])
            n += 1
        assert n > 0
        return True

    def mk_execution(self,force:bool=False)->None:

        if get_verbose():
            print(colored("Creating Execution Machine:","green"),self.execm_id)

        machine = self.machine
        queues : JList = [
          {
            "name" : machine.queue,
            "default" : True,
            "maxJobs" : machine.max_jobs,
            "maxNodes" : machine.max_nodes,
            "maxProcessorsPerNode" : machine.max_procs_per_node,
            "minProcessorsPerNode" : 1,
            "maxRequestedTime" : machine.max_run_time
          }
        ]
        execm : JDict = {
            "id" : self.execm_id,
            "name" : f"{machine.name} exec ({machine.user})",
            "description" : f"The {machine.name} execution computer",
            "site" : machine.domain,
            "public" : False,
            "status" : "UP",
            "type" : "EXECUTION",
            "executionType": "HPC",
            "scheduler" : machine.scheduler,
            "environment" : "",
            "scratchDir" : machine.scratch_dir,
            "workDir" : machine.work_dir,
            "login" : {
                "auth" : self.machine_auth,
                "host" : f"{machine.name}.{machine.domain}",
                "port" : machine.port,
                "protocol" : "SSH"
            },
            "maxSystemJobs" : machine.max_jobs,
            "maxSystemJobsPerUser" : machine.max_jobs_per_user,
            "queues" : queues,
            "storage" : {
                "host" : f"{machine.name}.{machine.domain}",
                "port" : machine.port,
                "protocol" : "SFTP",
                "rootDir" : machine.root_dir,
                "homeDir" : machine.home_dir,
                "auth" : self.machine_auth
            }
        }

        forkm = copy(execm)
        forkm["id"] = self.forkm_id
        forkm["scheduler"] = "FORK"
        forkm["executionType"] = "CLI"

        if machine.custom_directives is not None:
            directives = machine.custom_directives
            for q in queues:
                assert type(q) == dict
                q["customDirectives"] = directives

        assert execm["scheduler"] != "FORK"

        # EXEC
        if not force:
            headers = self.get_headers()
            response = requests.get(
                f'{self.baseurl}/systems/v2/{self.execm_id}', headers=headers)
            # This system is already defined.
            if response.status_code in success_codes:
                return

        if force or not self.check_machine(self.execm_id):
            json_execm = json.dumps(execm)
            headers = self.get_headers(json_execm)
            response = requests.post(
                f'{self.baseurl}/systems/v2/', headers=headers, data=json_execm)
            check(response)
            assert self.check_machine(self.execm_id)

        # FORK
        if not force:
            headers = self.get_headers()
            response = requests.get(
                f'{self.baseurl}/systems/v2/{self.forkm_id}', headers=headers)
            # This system is already defined.
            if response.status_code in success_codes:
                return

        if force or not self.check_machine(self.forkm_id):
            json_forkm = json.dumps(forkm)
            headers = self.get_headers(json_forkm)
            response = requests.post(
                f'{self.baseurl}/systems/v2/', headers=headers, data=json_forkm)
            check(response)
            assert self.check_machine(self.forkm_id)

    def mk_apps(self,force:bool=True)->None:

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
        app : JDict = {
            "name" : app_name,
            "version" : app_version,
            "label" : app_name,
            "shortDescription" : app_name,
            "longDescription" : app_name,
            "deploymentSystem" : self.storage_id,
            "deploymentPath" : self.deployment_path,
            "templatePath" : wrapper_file,
            "testPath" : test_file,
            "executionSystem" : self.execm_id,
            "executionType" : "HPC",
            "parallelism" : "PARALLEL",
            "allocation": "N/A",
            "modules":[],
            "inputs":[
                {   
                    "id":"input tarball",
                    "details":{  
                        "label":"input tarball",
                        "description":"",
                        "argument":"",
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
                    "validator": ""
                  },
                  "details": {
                    "label": "Singularity Image",
                    "description": "The Singularity image to run: swan, funwave",
                    "argument": "",
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
                    "validator": ""
                  },
                  "details": {
                    "label": "NX",
                    "description": "Processors in the X direction",
                    "argument": "",
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
                    "validator": ""
                  },
                  "details": {
                    "label": "NY",
                    "description": "Processors in the Y direction",
                    "argument": "",
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
                    "validator": ""
                  },
                  "details": {
                    "label": "NZ",
                    "description": "Processors in the Z direction",
                    "argument": "",
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
                    "argument": "",
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
                        "validator": "" 
                    }
                }
            ]
        }

        forkm_id = self.forkm_id
        fork_app_name = self.fork_app_name

        fork_app_id = self.fork_app_id
        forkapp = copy(app)
        forkapp["name"] = fork_app_name
        forkapp["executionSystem"] = forkm_id
        forkapp["executionType"] = "CLI"

        self.make_dir(self.deployment_path)
        self.make_dir(self.jobs_dir)

        home_dir = self.machine.home_dir

        self.file_upload(self.deployment_path,wrapper_file, wrapper)
        self.file_upload(self.deployment_path,test_file,wrapper_file)

        if get_verbose():
            print(colored("Make Queue App:","green"),app["name"])
        data = json.dumps(app)
        headers = self.get_headers(data)
        with open("json.txt", "w") as ff:
            print(data, file=ff)
        response = requests.post(f'{self.baseurl}/apps/v2/', headers=headers, data=data)
        check(response)

        if get_verbose():
            print(colored("Make Fork App:","green"),forkapp["name"])
        data = json.dumps(forkapp)
        headers = self.get_headers(data)
        response = requests.post(f'{self.baseurl}/apps/v2/', headers=headers, data=data)
        check(response)

    def file_upload(self, dir_name:str, file_name:str, file_contents:Optional[Union[str,bytes]]=None)->None:
        """
        Upload a file to a directory. The variable dir_name is relative
        to the home directory.
        """
        if get_verbose():
            if dir_name == "":
                dest = "."
            else:
                dest = dir_name
            print(colored("Uploading file:","green"),file_name,colored("to:","green"),dest)

        if file_contents is None:
            if get_verbose():
                print(colored("reading file:","magenta"),file_name)
            with open(file_name, "rb") as fd:
                file_contents = fd.read()
        headers = self.get_headers()
        files = {
            'fileToUpload': (file_name, file_contents)
        }
        url = f'{self.baseurl}/files/v2/media/system/{self.storage_id}/{dir_name}'
        pause()
        response = requests.post(url, headers=headers, files=files)
        check(response)

    def get_job_history(self, job_id:str)->JType:
        headers = self.get_headers()
        pause()
        response = requests.get(f"{self.baseurl}/jobs/v2/{job_id}/history/", headers=headers)
        if response.status_code == 404:
            return {}
        check(response)
        jdata : JDict = cast(JDict,response.json())
        return jdata["result"]

    def get_job_file(self,job_id:Union[str,JobBase],remote_file:str,local_file:Optional[str]=None)->bytes:

        if type(job_id) == str:
            jobid = job_id
        else:
            jobid = cast(JobBase,job_id).jobid

        if get_verbose():
            if local_file is not None:
                print(colored("Getting file:","green"), remote_file,colored("as:","green"),local_file)
            else:
                print(colored("Getting file:","green"), remote_file)
        headers = self.get_headers()
        pause()
        # Prevent double slashes
        remote_file = re.sub(r'^/','',remote_file)
        response = requests.get(f"{self.baseurl}/jobs/v2/{jobid}/outputs/media/{remote_file}", headers=headers)
        check(response)
        content = response.content
        is_binary = False
        for header in response.headers:
            if header.lower() == "content-type":
                if response.headers[header].lower() == "application/octet-stream":
                    is_binary = True
        if local_file is not None:
            if is_binary:
                fd = os.open(local_file,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o0644)
                os.write(fd,content)
                os.close(fd)
            else:
                with open(local_file,"wb") as fw:
                    fw.write(content)
        return content

    def hello_world_job(self, jtype:str='fork')->JobBase:
        """
        Create and send a "Hello World" job to make
        sure that the system is working.
        """
        input_tgz : tgz_type = {}

        return self.run_job(job_name='hello-world', script_file="hello-world", input_tgz=input_tgz, jtype=jtype, run_time="00:01:00")

    def run_job(self, job_name:str, script_file:str, input_tgz:tgz_type={}, jtype:str='fork',
            nodes:int=1, ppn:int=16, run_time:ostr=None, nx:int=0, ny:int=0, nz:int=0)->JobBase:
        """
        Run a job. It must have a name and an input tarball. It will default
        to running in a queue, but fork can also be requested. Specifying
        the run-time is a good idea, but not required.
        """
        if ppn == 0:
            ppn = self.machine.max_procs_per_node
        if nodes == 0:
            nodes = ceil(nx*ny*nz/ppn)

        if nx != 0 or ny != 0 or nz != 0:
            assert nx != 0 and ny != 0 and nz != 0
            assert nx*ny*nz <= ppn*nodes

        if nodes == 0:
            nodes = 1

        max_ppn = self.machine.max_procs_per_node
        assert ppn <= max_ppn, '%d <= %d' % (ppn, max_ppn)
        assert ppn >= 1
        assert nodes >= 1

        self.auth.refresh_token()

        input_tgz["metadata.txt"] = FileContents(json.dumps({
            "job-name":job_name,
            "jetlag-type":"tapis",
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

        if run_time is None:
            run_time = self.machine.max_run_time

        digits = 10
        max_val = 9e9
        while True:
            jid = idstr()
            tmp_job_name = job_name+"-"+jid
            status = self.get_job_status(tmp_job_name)
            if status is None:
                job_name = tmp_job_name
                break

        url = f"agave://{self.storage_id}/{self.jobs_dir}/{job_name}/"
        self.make_dir(self.jobs_dir)
        job_dir = self.jobs_dir+'/'+job_name+'/'
        self.make_dir(job_dir)
        self.file_upload(job_dir,"input.tgz")

        job = {
            "name":job_name,
            "appId": self.fork_app_id,
            "batchQueue": self.machine.queue,
            "maxRunTime": run_time,
            "nodeCount": nodes,
            "processorsPerNode": ppn,
            "archive": False,
            "archiveSystem": self.storage_id,
            "inputs": {
                "input tarball": url + "input.tgz"
            },
            "parameters": {
                "nx":nx,
                "ny":ny,
                "nz":nz,
                "script_name":script_file
            },
            "notifications": []
        }

        if jtype == 'fork':
            job['appId'] = self.fork_app_id
        elif jtype == 'queue':
            job['appId'] = self.app_id
        else:
            raise Exception("jtype="+jtype)
        
        notify = None

        if notify is not None:
            for event in job_done_status:
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

        data = json.dumps(job)
        headers = self.get_headers(data)
        response = requests.post(f'{self.baseurl}/jobs/v2/', headers=headers, data=data)
        check(response)
        rdata = response.json()
        job_id = rdata["result"]["id"]

        if get_verbose():
            print(colored("Job ID:","green"), job_id)
        jdata : JDict = {
            "jobid":job_id,
            "jetlag_id":self.jetlag_id
        }
        return TapisJob(self, jobid=job_id, jobname=job_name)

    def get_job_status(self, job_id:str)->Optional[JDict]:
        headers = self.get_headers()
        response = requests.get(f"{self.baseurl}/jobs/v2/{job_id}", headers=headers)
        if response.status_code == 404:
            return None
        check(response)
        jdata = cast(JDict,response.json()["result"])
        assert type(jdata) == dict
        return jdata

    def job_stop(self, jobid:str)->JType:
        data = json.dumps({ "action": "stop" })
        headers = self.get_headers(data)
        pause()
        response = requests.post(f"{self.baseurl}/jobs/v2/{jobid}", headers=headers, data=data)
        check(response)
        return cast(JType,response.json())

    def make_dir(self, dir_name:str)->None:
        """
        Create a directory relative to the home dir on the remote machine.
        """
        assert not re.match(r'^agave:',dir_name)
        if get_verbose():
            print(colored("Making Directory:","green"), dir_name)
        data = json.dumps({"action": "mkdir", "path": dir_name})
        headers = self.get_headers(data)
        pause()
        response = requests.put(
            f'{self.baseurl}/files/v2/media/system/{self.storage_id}/', headers=headers, data=data)
        check(response)

    def configure(self,force:bool=False)->bool:
        self.mk_storage(force)
        self.mk_execution(force)
        self.mk_apps(force)
        return True

    def get_job_file_list(self,jobid:str,dir:str='',recurse:bool=False)->List[str]:
        if dir == "" and get_verbose():
            print(colored("Output for job: "+jobid,"magenta"))

        headers = self.get_headers()
        params = ( ('limit', '100'), ('offset', '0'),)
        pause()
        response = requests.get(f"{self.baseurl}/jobs/v2/{jobid}/outputs/listings/{dir}", headers=headers, params=params)
        check(response)
        jdata = response.json()["result"]
        outs = []
        for fdata in jdata:
            fname = fdata["path"]
            if get_verbose():
                print(colored("File:","blue"),fname)
            if fdata["format"] == "folder":
                if recurse:
                    outs += self.get_job_file_list(jobid,fname,get_verbose())
                continue
            else:
                outs += [fname]
            if dir != '':
                continue
        return outs

    def get_access(self,app:str='queue')->List[str]:
        headers = self.get_headers()
        if app == 'fork':
            app_name = self.fork_app_name
        else:
            app_name = self.app_name
        version = self.app_version
        url = f"{self.baseurl}/apps/v2/{app_name}-{version}/pems"
        response = requests.get(url, headers=headers)
        if response.status_code == 403:
            print("error for url:",url)
        check(response)
        jdata : JDict = cast(JDict,response.json())
        result : List[str] = []
        for jd in cast(JList, link_filter(jdata["result"])):
            assert type(jd) == dict
            user : str = cast(str, jd["username"])
            perm : JDict = cast(JDict, jd["permission"])
            allow = True
            for m in ["read","write","execute"]:
                perm_val = perm["read"]
                assert type(perm_val) == bool
                allow = perm_val and allow
            if allow:
                result += [user]
        return result

    def system_role(self, system:str, user:str, role:str)->None:
        if get_verbose():
            print(colored("system role:","green"),user,"of",system,"=>",role)
        data = json.dumps({"role":role})
        headers = self.get_headers(data)
        
        url = f'{self.baseurl}/systems/v2/{system}/roles/{user}'
        response = requests.post(url, headers=headers, data=data)
        check(response)
        if get_verbose():
            print(colored("System Role:","green"),user,colored("of","green"),system,colored("=>","green"),role)

    def apps_pems(self, app:str, user:str, pem:str)->None:
        data = json.dumps({'permission': pem})
        headers = self.get_headers(data)

        url=f'{self.baseurl}/apps/v2/{app}/pems/{user}'
        response = requests.post(url, headers=headers, data=data)
        check(response)
        if get_verbose():
            print(colored("apps pems:","green"),user,colored("of","green"),app,colored("=>","green"),pem)

    def set_access(self, user:str, allow:bool)->bool:
        # Need to grant access to the meta data, the app, the exec machine, and the storage machine
        if allow:
            role = 'USER'
            apps_pems = 'READ_EXECUTE'
            meta_pems = 'READ'
        else:
            role = 'NONE'
            apps_pems = 'NONE'
            meta_pems = 'NONE'
        self.system_role(f'{self.execm_id}',user,role)
        self.system_role(f'{self.forkm_id}',user,role)
        self.system_role(f'{self.storage_id}',user,role)
        self.apps_pems(f'{self.app_name}-{self.app_version}',user,apps_pems)
        self.apps_pems(f'{self.fork_app_name}-{self.app_version}',user,apps_pems)
        access_str = colored("Access to:","green")
        if allow:
            print(access_str,f"{self.app_name} "+colored("granted","green")+" to user "+user)
        else:
            print(access_str,f"{self.app_name} "+colored("revoked","red")+" from user "+user)
        return True

class TapisJob(JobBase):
    def __init__(self, jetlag:TapisJetlag, jobid:str, jobname:str)->None:
        JobBase.__init__(self, jetlag, jobid, jobname)
        self.jlag = jetlag
        self.result : JType = {}
        self.jdata : JDict = {}
        self.last_status : str = ""

    def full_status(self)->Optional[JDict]:
        return self.jlag.get_job_status(self.jobid)

    def get_status(self)->Optional[str]:
        if self.last_status in job_done_status:
            return self.last_status
        jdata = self.full_status()
        assert jdata is not None
        self.jdata = jdata
        status = self.jdata["status"]
        assert type(status) == str
        self.last_status = status
        return self.last_status

    def stop(self)->JType:
        return self.jlag.job_stop(self.jobid)

    def get_result(self, force:bool=True)->JType:
        if self.result is not None:
            return self.result
        if self.get_status() == "FINISHED":
            jobdir="jobdata-"+self.jobid
            if not os.path.exists(jobdir):
                os.makedirs(jobdir, exist_ok=True)
            if not os.path.exists(os.path.join(jobdir,"output.tgz")):
                try:
                    self.jlag.get_job_file(self.jobid,"output.tgz",jobdir+"/output.tgz")
                    pcmd(["tar","xf","output.tgz"],cwd=jobdir)
                    if self.jdata is None:
                        self.status(self.jobid)
                except:
                    if get_verbose():
                        print(colored("Could not get output.tgz","red"))
            out_file = os.path.join(jobdir,"job.out")
            err_file = os.path.join(jobdir,"job.err")
            outs = self.jlag.get_job_file_list(self.jobid,recurse=False)
            for out in outs:
                g = re.match(r'.*(?:\.(out|err))$',out)
                if g:
                    tmp_file = os.path.join(jobdir, "job.%s" % g.group(1))
                    if not os.path.exists(tmp_file):
                        self.jlag.get_job_file(self.jobid, out, tmp_file)
            # Did the job create a result file that was consumable by Python?
            if os.path.exists(os.path.join(jobdir,'run_dir','result.json')):
                with open(os.path.join(jobdir,'run_dir','result.json'),"r") as fd:
                    val = fd.read().strip()
                    self.result = json.loads(val)
            else:
              self.result = None
            return self.result
        return {}

    def get_std_output(self)->str:
        out_file = os.path.join("jobdata-"+self.jobid,"job.out")
        if not os.path.exists(out_file):
            self.get_result()
        try:
            with open(out_file, "r") as fd:
                return fd.read()
        except FileNotFoundError as fnf:
            return ""

    def get_err_output(self)->str:
        out_file = os.path.join("jobdata-"+self.jobid,"job.err")
        if not os.path.exists(out_file):
            self.get_result()
        try:
            with open(out_file, "r") as fd:
                return fd.read()
        except FileNotFoundError as fnf:
            return ""

    def show_history(self)->None:
        print(colored("%17s:" % "Job","cyan"),self.jobid)
        history : JList = cast(JList,self.jetlag.get_job_history(self.jobid))
        last_secs = None
        for item in history:
            assert type(item) == dict
            dt, secs = from_agave_time(cast(str,item["created"]))
            if last_secs is None:
                last_secs = secs
            status : str = cast(str,item["status"])
            color = status_color.get(status, "white")
            ago_str = ago(secs - last_secs)
            secs = last_secs
            if ago_str == "":
                print(colored("%17s" % status,color),dt.strftime("%Y-%m-%d %H:%M:%S"))
            else:
                print(colored("%17s" % status,color),dt.strftime("%Y-%m-%d %H:%M:%S"),colored(ago_str,"yellow"))
            progress = item.get("progress",{})
            #if progress != {}:
            #    print('  ',end='')
            #    show_json(progress,indent=2)
