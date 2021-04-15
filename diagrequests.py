import requests
import os
import re
import sys
from contextlib import redirect_stdout
import pprint

def pprint(obj,indent=0):
    t = type(obj)
    if t in [list, set, tuple]:
        if t == tuple:
            print("tuple(")
        elif t == set:
            print("set{")
        else:
            print("list[")
        key = 0
        for elem in obj:
            print(" "*(indent+2),key,": ",end='',sep='')
            pprint(elem,indent=indent+2)
            key += 1
        if t == tuple:
            print(" "*indent,")",sep="")
        elif t == set:
            print(" "*indent,"}",sep="")
        else:
            print(" "*indent,"]",sep="")
    elif t == dict:
        print("dict{",sep="")
        for key in obj:
            val = obj[key]
            print(" "*(indent+2),key,": ",end='',sep='')
            pprint(val,indent=indent+2)
        print(" "*indent,"}",sep="")
    elif t == str:
        print('"',re.sub(r'"','\\"',obj),'"',sep='')
    else:
        print(obj)

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
    jetlag_debug = os.environ.get("JETLAG_DEBUG", "stdout")
    if jetlag_debug in ["stdout","1"]:
        debug_fd = sys.stdout
        print("Setting log to stdout")
    elif re.match(r'.*\.(txt|log)', jetlag_debug):
        print("Setting log to",jetlag_debug)
        debug_fd = open(jetlag_debug,"a+")
    elif jetlag_debug in ["0", "/dev/null", "no", "none"]:
        print("Setting log to none")
        debug_fd = None
    if verbose and debug_fd is None:
        debug_fd = sys.stdout

    if debug_fd is not None:
        assert debug_fd != sys.stdout
        with redirect_stdout(debug_fd):
            print()
            print("="*50)
            print("requests => ",mname,"(*args, **kargs)")
            print(" where ")
            print("args:")
            pprint(args)
            print("kargs:")
            k = 'Authorization'
            h = kargs.get("auth",None)
            if h is not None and type(h) == tuple:
                kargs["auth"] = (h[0],"[hidden]")
            h = kargs.get('headers',None)
            if h is not None:
                auth = h.get(k, None)
                if auth is not None:
                    h[k] = "[hidden]"
            else:
                auth = None
            pprint(kargs)
            if auth is not None:
                h[k] = auth
            print("="*50)
            print()
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
