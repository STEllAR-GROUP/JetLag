from jetlag import pp, mk_input, pcmd
from knownsystems import *
from time import sleep
import os
import sys
import html
import inspect
import codecs, pickle, re
from visualizeInTraveler import *

def to_string(obj):
    return re.sub(b'\\s',b'',codecs.encode(pickle.dumps(obj),'base64'))

def from_string(s):
    return pickle.loads(codecs.decode(s,'base64'))

def mk_label(fname, real_args):
    args = ''
    for i in range(len(real_args)):
      if i > 0:
        args += ','
      sa = str(real_args[i])
      if len(sa) > 5:
          sa = sa[0:5]+"..."
      args += str(sa)
    if len(args) > 10:
      args=args[0:10]+"..."
    return  html.escape(fname+"("+args + ")")



def viz(job,verbose=False):
    try:
      with open("run_dir/name.txt","r") as fd:
        fname = fd.read().strip()
      response = visualizeRemoteInTraveler(job.job_id,verbose=verbose)
    except Exception as e:
      print("Could not visualize result, Traveler missing/unavailable:")
      print("exception:",e)
      import traceback
      traceback.print_exc()

def remote_run(uv, fun, args, queue='fork', lim='00:05:00', nodes=0, ppn=0, script_name='phylanx'):
    if hasattr(fun, "backend"):
        wfun = fun.backend.wrapped_function
    else:
        wfun = fun
    funname = wfun.__name__
    src = inspect.getsource(wfun)
    pargs = to_string(args)
    label = mk_label(funname, args)

    input_tgz = {
      "filter.json" : open("/JetLag/filter.json", "r").read(),
      "py-src.txt" : src,
      "label.txt" : label,
      "name.txt" : funname,
      "py-args.txt" : pargs.decode()
    }
    job = uv.run_job('py-fun',input_tgz,jtype=queue,run_time=lim,nodes=nodes,ppn=ppn,script_name=script_name)
    return job
