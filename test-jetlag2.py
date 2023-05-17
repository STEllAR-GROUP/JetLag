from typing import Optional
import os
from jetlag import home, Machine, set_verbose, status_color, job_done_status, JobBase, show_json
from ssh_jetlag import SSHAuth, SSHJetlag
from colored import colored
from time import sleep

set_verbose(True)

auth = SSHAuth()
auth.refresh_token()
print("="*20)
ml = auth.systems_list()

machine = Machine(user='sbrandt',name='db1',domain='hpc.lsu.edu',definition_owner='tg457049',queue='checkpt')
auth.add_or_update_system(machine)

ml = auth.systems_list()
print("ml:",ml)
print("machine:",machine)

for m in ml:
    if m == machine:
        print("Found")

jetlag = SSHJetlag(auth, machine)
jetlag.configure(force=True)
job = jetlag.hello_world_job()
last_status = ""
while True:
    status = job.get_status()
    if status is None:
        print("Panic! status is none!")
        break
    if status != last_status:
        print(colored(status,status_color.get(status,"white")))
        last_status = status
    sleep(1)
    if status in job_done_status:
        break
job.get_result()
job.show_history()
