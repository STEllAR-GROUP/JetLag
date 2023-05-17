from typing import Optional
import os
from jetlag import home, Machine, set_verbose, status_color, job_done_status, JobBase, show_json
from tapis_jetlag import TapisAuth, TapisJetlag, TapisJob
from colored import colored
from time import sleep

set_verbose(True)

passwd : Optional[str]
with open(os.path.join(home, '.TAPIS_PASSWORD')) as fd:
    passwd = fd.read().strip()
passwd = None

auth = TapisAuth(user='tg457049',password=passwd,client='testclient')
auth.refresh_token()
print("="*20)
ml = auth.systems_list()

machine = Machine(user='sbrandt',name='db1',domain='hpc.lsu.edu',definition_owner='tg457049',queue='checkpt')
print(ml,machine)

for m in ml:
    if m == machine:
        print("Found")

jetlag = TapisJetlag(auth, machine)
#job : JobBase = TapisJob(jetlag,"f37343d8-bd41-4d37-bbb8-c95cfb644547-007","hello")
#job.show_history()
#jetlag.set_access('miao_s',False)
#print(jetlag.get_access())
#exit(0)
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
