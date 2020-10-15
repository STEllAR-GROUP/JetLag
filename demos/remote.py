__license__ = """
Copyright (c) 2020 R. Tohid (@rtohid)
Copyright (c) 2020 Steven R. Brandt (@stevenrbrandt)

Distributed under the Boost Software License, Version 1.0. (See accompanying
file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
"""

####
# The basic concept of universal is:
# (1) to use either Tapis or Agave
# (2) to describe a single machine that is:
#    (a) a storage machine
#    (b) an execution machine with FORK
#    (c) an execution machine with some scheduler
# (3) Has a generic app which
#    (a) takes input.tgz
#    (b) unpacks and executes run_dir/runapp.sh
#        from inside the run_dir/ directory
#    (c) packs everything up into output.tgz
#
#####
import hashlib, base64
import os
from jetlag.deployment.remote import Universal
import pprint
from math import log, ceil
from subprocess import Popen, PIPE
import sys
import re
import json
from time import sleep, time
from random import randint
#from tapis_config import *
from copy import copy, deepcopy
from datetime import datetime
import codecs, pickle
import importlib.machinery
from getpass import getpass

os.environ["AGAVE_JSON_PARSER"] = "jq"

job_done = ["FAILED", "FINISHED", "STOPPED", "BLOCKED"]


def codeme(m):
    t = type(m)
    if t == str:
        m = m.encode()
    elif t == bytes:
        pass
    else:
        raise Exception(str(t))
    h = hashlib.md5(m)
    v = base64.b64encode(h.digest())
    s = re.sub(r'[\+/]', '_', v.decode())
    return s[:-2]


def decode_bytes(bs):
    s = ''
    if type(bs) == bytes:
        for k in bs:
            s += chr(k)
    return s


has_color = False
if sys.stdout.isatty():
    try:
        # Attempt to import termcolor...
        from termcolor import colored
        has_color = True
    except:
        # If this fails, attempt to install it...
        try:
            from pip import main as pip_main
        except:
            try:
                from pip._internal import main as pip_main
            except:
                pass
        try:
            pip_main(["install", "--user", "termcolor"])
            has_color = True
        except:
            pass

if not has_color:
    # Don't colorize anything if
    # this isn't a tty
    def colored(a, _):
        return a


# Agave/Tapis uses all of these http status codes
# to indicate succes.
success_codes = [200, 201, 202]

pp = pprint.PrettyPrinter(indent=2)


def age(fname):
    "Compute the age of a file in seconds"
    t1 = os.path.getmtime(fname)
    t2 = time()
    return t2 - t1


last_time = time()


def old_pause():
    global last_time
    now = time()
    sleep_time = last_time + pause_time - now
    if sleep_time > 0:
        sleep(sleep_time)
    last_time = time()


time_array = []

pause_files = 5
pause_time = 30
poll_time = 5


def key2(a):
    return int(1e6 * a[1])


def pause():
    global time_array
    home = os.environ['HOME']
    tmp_dir = home + "/tmp/times"
    if len(time_array) == 0:
        os.makedirs(tmp_dir, exist_ok=True)
        time_array = []
        for i in range(pause_files):
            tmp_file = tmp_dir + "/t_" + str(i)
            if not os.path.exists(tmp_file):
                with open(tmp_file, "w") as fd:
                    pass
            tmp_age = os.path.getmtime(tmp_file)
            time_array += [[tmp_file, tmp_age - pause_time]]
    time_array = sorted(time_array, key=key2)
    stime = time_array[0][1] + pause_time
    now = time()
    delt = stime - now
    if delt > 0:
        sleep(delt)
    with open(time_array[0][0], "w") as fd:
        pass
    time_array[0][1] = os.path.getmtime(time_array[0][0])


last_time_array = []


def pause1():
    global last_time_array
    now = time()
    last_time_array += [now]

    nback = 3
    nsec = 10
    nmargin = 5

    if len(last_time_array) > nback:
        if now - last_time_array[-nback] < nsec:
            stime = nsec - now + last_time_array[-nback]
            sleep(stime)
    else:
        old_pause()
    if len(last_time_array) > nback + nmargin:
        last_time_array = last_time_array[-nback:]


def check(response):
    """
    Called after receiving a response from the requests library to ensure that
    an error was not received.
    """
    if response.status_code not in success_codes:
        requests.show()
        msg = str(response)
        if response.content is not None:
            msg += response.content.decode()
        raise Exception(msg)


def idstr(val, max_val):
    """
    This function is used to generate a unique
    id string to append to the end of each
    job name.
    """
    assert val < max_val
    d = int(log(max_val, 10)) + 1
    fmt = "%0" + str(d) + "d"
    return fmt % val


def pcmd(cmd, input=None, cwd=None):
    """
    Generalized pipe command with some convenient options
    """
    #print(colored(' '.join(cmd),"magenta"))
    p = Popen(cmd,
              stdin=PIPE,
              stdout=PIPE,
              stderr=PIPE,
              universal_newlines=True,
              cwd=cwd)
    if input is not None:
        print("send input...")
        out, err = p.communicate(input=input)
    else:
        out, err = p.communicate()
    print(colored(out, "green"), end='')
    if err != '':
        print(colored(err, "red"), end='')
    return p.returncode, out, err


# Read a file
def readf(fname):
    with open(fname, "r") as fd:
        return fd.read()


def check_data(a, b, prefix=[]):
    """
    Used to compare data sets to see if updating
    is needed. So far, only used for storage systems.
    """
    keys = set()
    keys.update(a.keys())
    keys.update(b.keys())
    err = 0
    for k in keys:
        if k in a and k not in b:
            if len(prefix) > 0 and prefix[-1] == "auth":
                pass
            else:
                print("only in a:", prefix + [k], "=>", a[k])
                err += 1
        elif k in b and k not in a:
            pass  #print("only in b:",k,"=>",b[k])
        elif type(a[k]) == dict and type(b[k]) == dict:
            err += check_data(a[k], b[k], prefix + [k])
        elif a[k] != b[k]:
            if len(prefix) > 0 and prefix[-1] == "auth":
                pass
            else:
                print("not equal:", prefix + [k], "=>", a[k], "!=", b[k])
                err += 1
    return err


def mk_input(input_tgz):
    """
    Generate a tarball from a hash of file names/contents.
    """
    pcmd(["rm", "-fr", "run_dir"])
    os.mkdir("run_dir")
    for k in input_tgz.keys():
        with open("run_dir/" + k, "w") as fd:
            print(input_tgz[k].strip(), file=fd)
    pcmd(["tar", "czf", "input.tgz", "run_dir"])


def load_input(pass_var, is_password):
    """
    Load a password either from an environment variable or a file.
    """
    if pass_var in os.environ:
        return os.environ[pass_var]

    pfname = os.environ["HOME"] + "/." + pass_var
    if os.path.exists(pfname):
        print("reading %s from %s..." % (pass_var, pfname))
        os.environ[pass_var] = readf(pfname).strip()
        return os.environ[pass_var]

    if is_password:
        os.environ[pass_var] = getpass(pass_var + ": ").strip()
    else:
        os.environ[pass_var] = input(pass_var + ": ").strip()

    if not os.path.exists(pfname):
        fd = os.open(pfname, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o0600)
        os.write(fd, os.environ[pass_var].encode('ASCII'))
        os.close(fd)

    return os.environ[pass_var]


class RemoteJobWatcher:
    def __init__(self, uv, jobid):
        self.uv = uv
        self.jobid = jobid
        self.last_status = "EMPTY"
        self.jdata = None

    def wait(self):
        s = None
        while True:
            self.uv.poll()
            n = self.status()
            if n != s:
                print(n)
                s = n
            sleep(poll_time)
            if n in job_done:
                return

    def stop(self):
        self.uv.job_stop(self.jobid)

    def get_result(self):
        if hasattr(self, "result"):
            return self.result
        if self.status() == "FINISHED":
            jobdir = "jobdata-" + self.jobid
            if not os.path.exists(jobdir):
                os.makedirs(jobdir, exist_ok=True)
                self.uv.get_file(self.jobid, "output.tgz",
                                 jobdir + "/output.tgz")
                pcmd(["tar", "xf", "output.tgz"], cwd=jobdir)
                if self.jdata is None:
                    self.status(self.jobid)
                outs = self.uv.show_job(self.jobid,
                                        verbose=False,
                                        recurse=False)
                for out in outs:
                    if re.match(r'.*(\.(out|err))$', out):
                        self.uv.get_file(
                            self.jobid, out,
                            jobdir + "/" + re.sub(r'.*\.', 'job.', out))
            if os.path.exists(jobdir + '/run_dir/result.py'):
                with open(jobdir + '/run_dir/result.py', "r") as fd:
                    # Mostly, PhySL data structures look like Python
                    # data structures. Unfortunately, PhySL will
                    # construct a list as list(1,2,3). This is illegal
                    # in Python. Convert to list((1,2,3)). A more
                    # general solution is probably needed.
                    val = fd.read().strip()
                    if re.match(r'^list\(', val):
                        val = 'list(' + re.sub(r'^list', '', val) + ')'
                    try:
                        self.result = eval(val)
                    except Exception as e:
                        self.result = val
            else:
                self.result = None
            return self.result
        return None

    def diag(self):
        """
        Diagnose a job to see
        whether it worked or
        what might have caused
        it to fail.
        """
        f = self.full_status()
        if "lastStatusMessage" in f:
            print("Last Status:", f["lastStatusMessage"])
        h = self.history()
        print("History:")
        if len(h) > 3:
            pp.pprint(h[-3:])
        else:
            pp.pprint(h)

    def full_status(self):
        return self.uv.job_status(self.jobid)

    def status(self):
        if self.last_status in job_done:
            return self.last_status
        self.jdata = self.full_status()
        self.last_status = self.jdata["status"]
        return self.last_status

    def history(self):
        return self.uv.job_history(self.jobid)

    def err_output(self):
        self.get_result()
        try:
            with open("jobdata-" + self.jobid + "/job.err", "r") as fd:
                return fd.read()
        except FileNotFoundError as fnf:
            return ""

    def std_output(self):
        self.get_result()
        try:
            with open("jobdata-" + self.jobid + "/job.out", "r") as fd:
                return fd.read()
        except FileNotFoundError as fnf:
            return ""


if __name__ == "__main__":
    uv = Universal()
    print('done!!!')
    backend = sys.argv[1]
    if len(sys.argv) > 2:
        system = sys.argv[2]
    else:
        system = None
    if system == "None":
        system = None
    uv.load(backend=backends[backend],
            notify='sbrandt@cct.lsu.edu',
            jetlag_id=system)
    uv.refresh_token()
    if len(sys.argv) <= 3:
        pass
    elif sys.argv[3] in ["job-status", "status"]:
        j1 = RemoteJobWatcher(uv, sys.argv[4])
        pp.pprint(j1.full_status())
    elif sys.argv[3] in ["last-job-status", "last-status"]:
        j1 = RemoteJobWatcher(uv, sys.argv[4])
        pp.pprint(j1.full_status()["lastStatusMessage"])
    elif sys.argv[3] == "get-result":
        j1 = RemoteJobWatcher(uv, sys.argv[4])
        j1.get_result()
    elif sys.argv[3] == "poll":
        uv.poll()
    elif sys.argv[3] == "del-meta":
        n = 0
        d = {"uuid": sys.argv[4]}
        uv.del_meta(d)
    elif sys.argv[3] == "set-meta":
        meta = {'name': sys.argv[4], 'value': sys.argv[5]}
        uv.set_meta(meta)
    elif sys.argv[3] == "meta":
        n = 0
        for m in uv.get_meta(sys.argv[4]):
            n += 1
            print(n, ": ", sep='', end='')
            pp.pprint(m)
    elif sys.argv[3] == "jobs":
        if 4 < len(sys.argv):
            nj = int(sys.argv[4])
        else:
            nj = 10
        for j in uv.job_list(nj):
            pp.pprint(j)
    elif sys.argv[3] == "history":
        jobid = sys.argv[4]
        hist = uv.job_history(jobid)
        pp.pprint(hist)
    elif sys.argv[3] == 'job-name':
        jdata = uv.job_by_name(sys.argv[4])
        pp.pprint(jdata)
    elif sys.argv[3] == 'cleanup':
        uv.job_cleanup()
    elif sys.argv[3] == 'hello':
        jobid = uv.hello_world_job()
        jw = RemoteJobWatcher(uv, jobid)
        jw.wait()
    elif sys.argv[3] == 'get-file':
        jobid = sys.argv[4]
        fname = sys.argv[5]
        c = uv.get_file(jobid, fname)
        print(decode_bytes(c))
    elif sys.argv[3] == 'ssh-config':
        uv.configure_from_ssh_keys()
    elif sys.argv[3] == 'access':
        user = sys.argv[4]
        if sys.argv[5] == "True":
            tf = True
        elif sys.argv[5] == "False":
            tf = False
        else:
            assert False, "arg 5 should be True/False"
        print("Access:", user, tf)
        uv.access(user, tf)
    elif sys.argv[3] == 'systems':
        for sys in uv.systems():
            print(sys)
    elif sys.argv[3] == 'systems':
        uv.systems()
    elif sys.argv[3] == 'mkdir':
        uv.make_dir(sys.argv[4])
    elif sys.argv[3] == 'jetlagid':
        pp.pprint(uv.jetlag_ids())
    else:
        raise Exception(sys.argv[3])

    print('Done!!!')