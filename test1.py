#!/usr/bin/env python3
from jetlag import Auth, JetLag, pp, mk_input, pcmd, RemoteJob, set_verbose, clone_machine
from knownsystems import *

from time import sleep
import os
import html
import re

set_verbose(True)
auth = Auth(utype='tapis', user='tg457049')
auth.create_or_refresh_token()
#os.unlink(auth.get_auth_file())
#auth = Auth(utype='tapis', user=os.environ["TEST_USER"])
#auth.create_or_refresh_token()

rostam["work_dir"]='/work/sbrandt'
rostam["scratch_dir"]='/work/sbrandt'
rostam["root_dir"]='/'
rostam["home_dir"]='/home/sbrandt/root/home'
uv = JetLag(auth,
  **rostam
)
uv.configure()
if False:
  uv = clone_machine(auth,
    name='rostam-sbrandt-exec-tg457049',
    user="sbrandt",
    work_dir='/work/sbrandt',
    scratch_dir='/work/sbrandt',
    root_dir="/",
    home_dir="/home/sbrandt/root/home")
uv.configure()

j1 = uv.hello_world_job('fork')
print("Job was submitted")
j1.wait()
assert j1.status() == "FINISHED"
err = j1.err_output()
assert re.search(r'(?m)^This is stderr', err), err
out = j1.std_output()
assert re.search(r'(?m)^This is stdout', out), out

if True: 
    j2 = uv.hello_world_job('queue')
    print("Job was submitted")
    j2.wait()
    assert j2.status() == "FINISHED"
else:
    print("Test skipped: Agave can't queue on slurm")


print("Test passed")
exit(0)
