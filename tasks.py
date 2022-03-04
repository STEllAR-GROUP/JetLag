import threading as th
from traceback import print_exc
import sys
import os
import re

taskidmap = {}

taskid = 1000

class Task(th.Thread):
    def __init__(self,f,a):
        global taskid
        th.Thread.__init__(self)
        self.func = f
        self.args = a
        self.status = "PENDING"
        self.taskid = "%d-%d" % (os.getpid(),taskid)
        taskid += 1
        taskidmap[self.taskid] = self
        self.out = None
        self.err = None
        self.retcode = None
        self.ex = None

    def run(self):
        self.status = "RUNNING"
        try:
            self.out, self.err, self.retcode = self.func(*self.args)
        except Exception as ex:
            print_exc(file=sys.stdout)
            self.ex = ex
            self.out, self.err, self.retcode = "", str(ex), -1
        finally:
            if self.retcode == 0:
                self.status = "FINISHED"
            else:
                self.status = "FAILED"

def run_task(f,a):
    task = Task(f,a)
    task.start()
    return task.taskid

def task_status(task_id):
    assert type(task_id) == str
    task = taskidmap.get(task_id, None)

    if task is None:
        try:
            g = re.match(r'(\d+)-(\d+)', task_id)
            if g:
                pid = int(g.group(1))
                os.kill(pid, 0)
        except ProcessLookupError as err:
            return { "status": "FAILED" }
        return None

    ret = {
        "status": task.status,
        "out": task.out,
        "err": task.err,
        "cmd": str(task.args),
        "retcode": task.retcode
    }
    if task.ex is not None:
      ret["reason"] = str(task.ex)
    if not task.isAlive():
      task.join()
    return ret
