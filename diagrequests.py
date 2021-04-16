import requests
import os
import re
import sys
from contextlib import redirect_stdout
import pprint
from datetime import datetime

hidden = set()

def pprint(obj,indent=0,fd=sys.stdout):
    t = type(obj)
    if t in [list, set, tuple]:
        if t == tuple:
            print("tuple(",file=fd)
        elif t == set:
            print("set{",file=fd)
        else:
            print("list[",file=fd)
        key = 0
        for elem in obj:
            print(" "*(indent+2),key,": ",end='',sep='',file=fd)
            pprint(elem,indent=indent+2,fd=fd)
            key += 1
        if t == tuple:
            print(" "*indent,")",sep="",file=fd)
        elif t == set:
            print(" "*indent,"}",sep="",file=fd)
        else:
            print(" "*indent,"]",sep="",file=fd)
    elif t == dict:
        print("dict{",sep="",file=fd)
        for key in obj:
            val = obj[key]
            print(" "*(indent+2),key,": ",end='',sep='',file=fd)
            pprint(val,indent=indent+2,fd=fd)
        print(" "*indent,"}",sep="",file=fd)
    elif t == str:
        if obj in hidden:
            print("[hidden]",file=fd)
        else:
            print('"',re.sub(r'"','\\"',obj),'"',sep='',file=fd)
    else:
        print(obj,file=fd)

save = None

verify_ssl_env = os.environ.get("VERIFY_SSL","yes").lower()
assert verify_ssl_env in ["yes", "no"], "VERIFY_SSL must be YES or NO"
verify_ssl = verify_ssl_env == "yes"
debug_fd = None

if verify_ssl == False:
    if "PYTHONWARNINGS" not in os.environ:
        print("Disabling SSL Verification, consider setting env variable...")
        print("export PYTHONWARNINGS='ignore:Unverified HTTPS request'")
    else:
        print("Disabling SSL Verification")

def all(mname, args, kargs, verbose=False):
    global save
    jetlag_debug = os.environ.get("JETLAG_DEBUG", "0")
    if jetlag_debug in ["stdout","1"]:
        debug_fd = sys.stdout
    elif re.match(r'.*\.(txt|log)', jetlag_debug):
        debug_fd = open(jetlag_debug,"a+")
    elif jetlag_debug in ["0", "/dev/null", "no", "none"]:
        debug_fd = None
    if verbose and debug_fd is None:
        debug_fd = sys.stdout

    if debug_fd is not None:
        print(file=debug_fd)
        print("="*50,file=debug_fd)
        print(datetime.now(),file=debug_fd)
        print("requests => ",mname,"(*args, **kargs)",file=debug_fd)
        print(" where ",file=debug_fd)
        print("args:",file=debug_fd)
        pprint(args,fd=debug_fd)
        print("kargs:",file=debug_fd)
        k = 'Authorization'
        h = kargs.get("auth",None)
        if h is not None and type(h) == tuple:
            hidden.add(h[1])
        h = kargs.get('headers',None)
        if h is not None:
            auth = h.get(k, None)
            if auth is not None:
                hidden.add(h[k])
        else:
            auth = None
        pprint(kargs,fd=debug_fd)
        if auth is not None:
            h[k] = auth
        print("="*50,file=debug_fd)
        print(file=debug_fd)
    else:
        save = (mname, args, kargs)

def show():
    if save is not None:
        all(save[0], save[1], save[2], True)

def get(*args,**kargs):
    all("get",args,kargs)
    kargs["verify"] = verify_ssl
    return requests.get(*args,**kargs)

def post(*args,**kargs):
    all("post",args,kargs)
    kargs["verify"] = verify_ssl
    return requests.post(*args,**kargs)

def delete(*args,**kargs):
    all("delete",args,kargs)
    kargs["verify"] = verify_ssl
    return requests.delete(*args,**kargs)

def put(*args,**kargs):
    all("put",args,kargs)
    kargs["verify"] = verify_ssl
    return requests.put(*args,**kargs)
