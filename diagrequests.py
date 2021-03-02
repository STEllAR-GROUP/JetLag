import pprint
import requests
import os
pp = pprint.PrettyPrinter(indent=4)

save = None

verify_ssl_env = os.environ.get("VERIFY_SSL","yes").lower()
assert verify_ssl_env in ["yes", "no"], "VERIFY_SSL must be YES or NO"
verify_ssl = verify_ssl_env == "yes"

if verify_ssl == False:
    if "PYTHONWARNINGS" not in os.environ:
        print("Disabling SSL Verification, consider setting env variable...")
        print("export PYTHONWARNINGS='ignore:Unverified HTTPS request'")
    else:
        print("Disabling SSL Verification")

def all(mname, args, kargs, verbose=False):
    global save
    if "JETLAG_DEBUG" in os.environ or verbose:
        print()
        print("="*50)
        print("requests => ",mname,"(*args, **kargs)")
        print(" where ")
        print("args:")
        pp.pprint(args)
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
        pp.pprint(kargs)
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
