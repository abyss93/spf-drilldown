import subprocess
import sys

def bash_command(cmd):
    process = subprocess.Popen(cmd, shell=True, executable='/bin/bash', stdout=subprocess.PIPE)
    return process.stdout.read().decode("utf-8")

def parse(elem):
    op = ""
    value = ""
    if elem.startswith("+"):
        op = "+"
    elif elem.startswith("-"):
        op = "-"
    elif elem.startswith("?"):
        op = "?"
    elif elem.startswith("~"):
        op = "~"
    elem = elem.replace(op, "")
    mechanism = elem

    if ":" in elem and not "ip6" in elem:
        r = elem.split(":")
        mechanism = r[0]
        value = r[1]
    elif "ip6" in elem:
        i = elem.index(":")
        mechanism = elem[:i]
        value = elem[i + 1:]
    if "=" in elem:
        r = elem.split("=")
        mechanism = r[0]
        value = r[1]
    return op, mechanism, value

def check_spf(domain, nest_lvl):
    nest_lvl = nest_lvl + 1
    print("\t" * nest_lvl + "CHECKING DOMAIN: " + domain)
    res = bash_command("dig " + domain + " txt | grep spf1 | grep -o '\".*\"' | sed 's/\"//g'")
    #print(res)
    elements = res.split()
    for e in elements:
        op, mechanism, value = parse(e)
        #print(op +" "+ mechanism +" "+ value)
        print("\t" * nest_lvl + "MECHANISM: " + str.upper(mechanism))
        if mechanism == "v":
            print("\t" * nest_lvl + "SPF Version: " + value)
        elif mechanism == "ip4" or  mechanism == "ip6":
            print("\t" * nest_lvl + op + value)
        elif mechanism == "a":
            if value == "":
                res_a = bash_command("dig " + domain + " a | grep -v \"^;\" | awk -F' ' '{print $5}' | grep -v \"^$\"")
            else:
                res_a = bash_command("dig " + value + " a | grep -v \"^;\" | awk -F' ' '{print $5}' | grep -v \"^$\"")
            for r in res_a.split("\n"):
                print("\t" * nest_lvl + op + r)   
        elif mechanism == "mx":
            if value == "":
                res_mx = bash_command("dig " + domain + " mx | grep -v \"^;\" | awk -F' ' '{print $6}' | grep -v \"^$\"")
            else:
                res_mx = bash_command("dig " + value + " mx | grep -v \"^;\" | awk -F' ' '{print $6}' | grep -v \"^$\"")
            for r in res_mx.split():
                print("\t" * nest_lvl + op + r)
        elif mechanism == "include":
            check_spf(value, nest_lvl)
        elif mechanism == "all":
            print("\t" * nest_lvl + op + "all")

if __name__ == "__main__":
    domain = sys.argv[1]
    check_spf(domain, -1)