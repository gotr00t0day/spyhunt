from modules import useragent_list
import subprocess

user_agent = useragent_list.get_useragent()
header = {"User-Agent": user_agent}

def commands(cmd):
    try:
        subprocess.check_call(cmd, shell=True)
    except:
        pass

def scan(command: str) -> str:
    cmd = command
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, err = p.communicate()
    out = out.decode() 
    return out
