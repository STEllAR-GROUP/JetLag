from jetlag import Universal, pp, mk_input, pcmd, RemoteJobWatcher
from knownsystems import *
from time import sleep
import os
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



def viz(job):
    #import importlib.machinery
    try:
      #if os.path.exists('run_dir/result.py'):
      #  modulename = importlib.machinery.SourceFileLoader('rr','run_dir/result.py').load_module()
      #  job.result = pickle.loads(codecs.decode(modulename.result,'base64'))
      #else:
      #  job.result = None
      with open("run_dir/name.txt","r") as fd:
        fname = fd.read().strip()
      response = visualizeRemoteInTraveler(job.jobid)
    except Exception as e:
      print("exception:",e)
      import traceback
      traceback.print_exc()

def remote_run(uv, fun, args, queue='fork', lim='00:05:00'):
    if hasattr(fun, "backend"):
        wfun = fun.backend.wrapped_function
    else:
        wfun = fun
    funname = wfun.__name__
    src = inspect.getsource(wfun)
    pargs = to_string(args)
    label = mk_label(funname, args)

    input_tgz = {
      "py-src.txt" : src,
      "label.txt" : label,
      "name.txt" : funname,
      "runapp.sh" : """#!/bin/bash
export CPUS=$(lscpu | grep "^CPU(s):"|cut -d: -f2)
export APEX_OTF2=1
export APEX_PAPI_METRICS="PAPI_TOT_CYC PAPI_BR_MSP PAPI_TOT_INS PAPI_BR_INS PAPI_LD_INS PAPI_SR_INS PAPI_L1_DCM PAPI_L2_DCM"
LD_LIBRARY_PATH="/home/jovyan/install/phylanx/lib64/phylanx:/home/jovyan/install/phylanx/lib64:/usr/local/lib64:/home/jovyan/install/phylanx/lib/phylanx:/usr/lib64/openmpi/lib"
export PYTHONPATH="/home/jovyan/.local/lib/python3.6/site-packages/phylanx-0.0.1-py3.6-linux-x86_64.egg"
singularity exec ~/images/phylanx-test.simg python3 command.py
""",
      "command.py" : """#!/usr/bin/env python3
from phylanx import Phylanx, PhylanxSession
import codecs, pickle, re, os

cpus = int(os.environ["CPUS"].strip())
PhylanxSession.init(16)

def to_string(obj):
    return re.sub(b'\\s',b'',codecs.encode(pickle.dumps(obj),'base64'))

def from_string(s):
    return pickle.loads(codecs.decode(s,'base64'))

args = from_string({argsrc})

@Phylanx
{funsrc}

with open("call_{funname}.physl","w") as fw:
    alist = []
    aasign = []
    for i in range(len(args)):
        argn = "a"+str(i)
        alist += [argn]
        aasign += ["define(",argn+","+str(args[i])+")"]
    from phylanx.ast.physl import print_physl_src
    import contextlib, io
    physl_src_raw = {funname}.get_physl_source()
    f = io.StringIO()
    with contextlib.redirect_stdout(f):
        print_physl_src(physl_src_raw)
    physl_src_pretty = f.getvalue()
    print(physl_src_raw,file=fw)

    for a in aasign:
        print(a,file=fw)
    print("cout({funname}("+(",".join(alist))+"))",file=fw)

from subprocess import Popen, PIPE
p = Popen([
        "mpirun",
        "-np","1",
        "/home/jovyan/phylanx/build/bin/physl",
        "--dump-counters=py-csv.txt",
        "--dump-newick-tree=py-tree.txt",
        "--dump-dot=py-graph.txt",
        "--performance",
        "call_{funname}.physl"
    ]
    ,stdout=PIPE,stderr=PIPE,universal_newlines=True)
out, err = p.communicate()

# This is redundant and shouldn't be needed
# once physl can write the result to a file.
result = {funname}(*args)

with open("result.py","w") as fd:
    sval = to_string(result)
    print("result=%s" % sval,file=fd)

with open("physl-src.txt","w") as fd:
    print(physl_src_pretty,file=fd)

""".format(funsrc=src, funname=funname, argsrc=pargs)
    }
    jobid = uv.run_job('py-fun',input_tgz,jtype=queue,run_time=lim,nodes=1)
    return RemoteJobWatcher(uv,jobid)
