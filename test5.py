#!/usr/bin/env python3
from jetlag import Auth, JetLag, pp, mk_input, pcmd, RemoteJob, set_verbose
from knownsystems import *
import re
from time import sleep
import os
import html

set_verbose(True)

# Test creation of shelob configuration using Agave
auth = Auth(utype='tapis', user=os.environ["TEST_USER"])
auth.create_or_refresh_token()
uv = JetLag(auth, machine='rostam', machine_user='sbrandt', owner='tg457049')

j1 = uv.hello_world_job('fork',sleep_time=15)
print("Job was submitted")
j1.stop()
j1.wait()
assert j1.status() == "STOPPED"

print("Test passed")
exit(0)
