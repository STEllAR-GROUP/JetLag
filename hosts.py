import os
import re

home = os.environ["HOME"]

def get_ssh_data():
    ssh_config = os.path.join(home, ".ssh", "config")
    ssh_data = {}
    host = None
    if os.path.exists(ssh_config):
        with open(ssh_config,"r") as fd:
            ssh_data = {}
            for line in fd.readlines():
                line = line.strip()
                line = re.sub(r'#.*','',line)
                g = re.match(r'^(\S+)\s+(.+)', line)
                if g:
                    key, value = g.group(1).lower(), re.sub(r'^=\s*','',g.group(2))
                    if key.lower() == "host" and value not in ssh_data:
                        host = value
                        ssh_data[host] = {}
                    else:
                        ssh_data[host][key] = value
    return ssh_data

def set_ssh_data(host,key,value):
    assert type(host) == str, "Host must be a str"
    assert type(key) == str, "Key must be a str"
    assert value is None or type(value) == str, "Value must be a str or None"
    host = host.strip().lower()
    key = key.strip().lower()
    assert re.match(r'^[a-zA-Z][a-zA-Z0-9_\.]+$',host), "Bad host string"
    assert re.match(r'^[a-zA-Z][a-zA-Z0-9_]+$',key), "Bad key string"
    ssh_config = os.path.join(home, ".ssh", "config")
    ssh_data = get_ssh_data()
    if host not in ssh_data:
       ssh_data[host] = {}
    if value is None:
      del ssh_data[host][key]
    else:
      ssh_data[host][key] = value
    if len(ssh_data[host]) == 0:
      del ssh_data[host]
    with open(ssh_config, "w") as fd:
      for host in ssh_data:
          print("Host",host,file=fd)
          host_data = ssh_data[host]
          for key in host_data:
              print("   ",key,host_data[key],file=fd)

def has_host_key(host):
    host = host.strip().lower()
    ssh_data = get_ssh_data()
    if host in ssh_data:
        if "hostname" in ssh_data[host]:
            host = ssh_data[host]["hostname"]
    known_hosts = os.path.join(home, ".ssh", "known_hosts")
    with open(known_hosts, "r") as fd:
        for line in fd.readlines():
            cols = line.strip().split(',')
            if cols[0].lower() == host.lower():
                return True
    return False

def set_ssh_persist(host):
    set_ssh_data(host,"ControlMaster","auto")
    set_ssh_data(host,"ControlPath","~/.ssh/control-%h-%p-%r")
    set_ssh_data(host,"ControlPersist","1m")

if __name__ == "__main__":
    ssh_data = get_ssh_data()
    for host in ssh_data:
        print(host)
        host_data = ssh_data[host]
        for key in host_data:
            print("   ",key,host_data[key])
    print("has host key:",has_host_key("db"))
    print("has host key:",has_host_key("db1.hpc.lsu.edu"))
