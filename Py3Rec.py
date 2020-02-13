#!/usr/bin/env python3
# -*- coding: utf-8 -*-


"""
PyRecon - A very simple tool to gather information about a target system.
It puts efforts in simplicity, compatibility and portability.
The idea is that it can help in identify system information
to help in support or as a payload in a pentest to recon some more information.
"""


from time import tzname, asctime
from sys import exit, version_info, platform
from socket import socket, AF_INET, SOCK_DGRAM
from os import getcwd, getgid, getuid, chdir, listdir
from getpass import getuser
from platform import uname
from locale import getlocale


# Import for both Python 3 request(urllib) flows as well in case we don't have requests available
from time import perf_counter as time
try:
    from requests import get
    alternative_method = False
except (ImportError, ModuleNotFoundError):
    from urllib import request
    alternative_method = True


def get_external_ip():
    """Function to get the external ip of the target machine

    It have 2 possibles flows:
    1. Python 3 and requests lib available
    2. Python 3 and urllib.requests.urlopen available

    https://api.ipify.org or https://ifconfig.me/
    """
    if alternative_method is False:
        external = get("https://api.ipify.org").text
    else:
        external = request.urlopen("https://api.ipify.org").read().decode("utf8")
    return external


def get_local_ip(ip="8.8.8.8"):
    """Function that uses stdlib functions collect info about the target internal ip.

    Positional arguments:
    ip -- a ip to connect for testing (default 8.8.8.8 Google Public DNS)

    """


    s = socket(AF_INET, SOCK_DGRAM)
    s.connect((ip, 80))
    internal = (s.getsockname()[0])
    s.close()
    return internal


def get_software():
    """Function that uses stdlib functions collect info about the target OS."""


    print("[+] Hostname:        {}".format(uname()[1]))
    print("[+] OS:              {}".format(uname()[0]))
    print("[+] Arch:            {}".format(uname()[4]))
    print("[+] CPU:             {}".format(uname()[5]))
    print("[+] Kernel:          {}".format(uname()[2]))
    print("[+] Kernel version:  {}".format(uname()[3]))


def get_user():
    """Function that uses stdlib functions to collect info about the user that executed the script."""


    user = getuser()
    print("[+] User:    {}".format(user))
    print("[+] UID:     {}".format(getuid()))
    print("[+] GID:     {}".format(getgid()))
    return user


def localization():
    """Function that uses stdlib functions to collect info about the user/system localization."""
    

    print("[+] Locale:      LANG={} CE={}".format(getlocale()[0], getlocale()[1]))
    print("[+] Time:        {}".format(asctime()))
    print("[+] Timezone:    Normal:{} DST:{}".format(tzname[0], tzname[1]))


def get_open_ports(local_ip="127.0.0.1"):
    """Function that uses stdlib functions to collect info about the open ports at the target system.

    Positional arguments:
    local_ip -- the local ip to scan, also it can be by DHCP like 192.1XX.XXX.XXX (default 127.0.0.1)
    """
    port = 0
    connected = False
    while port <= 65535:
        try:
            try:
                s = socket()
            except OSError:
                print("Error: Can not create socket!")
                break
            else:
                s.connect((local_ip, port))
                connected = True
        except ConnectionError:
            connected = False
        finally:
            if connected is True and port != s.getsockname()[1]:
                print("[*] OPEN PORT --> {0}:{1}".format(local_ip, port))
            port = port + 1
            s.close()


def list_bytes(user):
    cwd = getcwd()
    print("[+] CWD:     {}".format(cwd))
    print("[+] Content:")
    content = listdir(cwd)
    for item in content:
        print("   [*] {}".format(item))
    if platform.startswith("linux"):
        print("[*] Linux home")
        path = "/home/" + user
    chdir(path)
    print("[+] Home:    {}".format(path))
    print("[+] Content:")
    content = listdir(path)
    for item in content:
        print("   [*] {}".format(item))


def main():
    try:
        version = "V=Strike_0ne_"
        print("-"*80)
        print("PyRecon {0}".format(version))
        print("-"*80)
        start = time()
        print("-"*80)
        print("OS Info")
        print("-"*80)
        get_software()
        print("-"*80)
        print("-"*80)
        print("User Info")
        print("-"*80)
        user = get_user()
        list_bytes(str(user))
        print("-"*80)
        print("-"*80)
        print("Localization Info")
        print("-"*80)
        localization()
        print("-"*80)
        print("-"*80)
        print("Network Info")
        print("-"*80)
        internal = get_local_ip()
        external = get_external_ip()
        print("[+] Local IP:    {}".format(internal))
        print("[+] External IP: {}".format(external))
        print("-"*80)
        get_open_ports(str(internal))
        print("-"*80)
        stop = time()
        print("Time of recon")
        print("-"*80)
        print("[*] Time elapsed = {:.2f} seconds".format(stop - start))
        print("-"*80)
        exit(0)
    except KeyboardInterrupt:
        print("Aborting...")
        exit(1)


if __name__ == "__main__":
    main()

