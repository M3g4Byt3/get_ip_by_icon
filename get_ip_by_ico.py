#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import mmh3
import requests
import argparse
from urllib.parse import urlparse
from shodan import Shodan
import base64
import pdb
import codecs

api = Shodan('your key')

LOGO = R"""
  ▄████ ▓█████▄▄▄█████▓ ██▓ ██▓███   ▄▄▄▄ ▓██   ██▓ ██▓ ▄████▄   ▒█████  
 ██▒ ▀█▒▓█   ▀▓  ██▒ ▓▒▓██▒▓██░  ██▒▓█████▄▒██  ██▒▓██▒▒██▀ ▀█  ▒██▒  ██▒
▒██░▄▄▄░▒███  ▒ ▓██░ ▒░▒██▒▓██░ ██▓▒▒██▒ ▄██▒██ ██░▒██▒▒▓█    ▄ ▒██░  ██▒
░▓█  ██▓▒▓█  ▄░ ▓██▓ ░ ░██░▒██▄█▓▒ ▒▒██░█▀  ░ ▐██▓░░██░▒▓▓▄ ▄██▒▒██   ██░
░▒▓███▀▒░▒████▒ ▒██▒ ░ ░██░▒██▒ ░  ░░▓█  ▀█▓░ ██▒▓░░██░▒ ▓███▀ ░░ ████▓▒░
 ░▒   ▒ ░░ ▒░ ░ ▒ ░░   ░▓  ▒▓▒░ ░  ░░▒▓███▀▒ ██▒▒▒ ░▓  ░ ░▒ ▒  ░░ ▒░▒░▒░ 
  ░   ░  ░ ░  ░   ░     ▒ ░░▒ ░     ▒░▒   ░▓██ ░▒░  ▒ ░  ░  ▒     ░ ▒ ▒░ 
░ ░   ░    ░    ░       ▒ ░░░        ░    ░▒ ▒ ░░   ▒ ░░        ░ ░ ░ ▒  
      ░    ░  ░         ░            ░     ░ ░      ░  ░ ░          ░ ░  
                                          ░░ ░         ░                                                          
                                          ░░ ░         ░                                                          
"""

look = codecs.lookup('base64')
def getfaviconhash(url):
    try:
        response = requests.get(url)
        #pdb.set_trace()
        if response.headers['Content-Type'] == "image/x-icon":
            favicon = look.encode(response.content)
            #favicon = response.content.decode('base64')
            hashs = mmh3.hash(favicon[0])
        else:
            hashs = None
    except Exception as e:
        print(e)
        print("[!] Request Error")
        hashs = None
    return hashs


def queryshodan(url):
    o = urlparse(url)
    if len(o.path)>=2:
        url = url
    else:
        url = url+"/favicon.ico"
    try:
        hash = getfaviconhash(url)
        if hash:
            query = "http.favicon.hash:{}".format(hash)
            count = api.count(query)['total']
            if count == 0:
                print("[-] No result")
            else:
                print("[+] Try to get {} ip.".format(count))
                for hosts in api.search_cursor(query):
                    print("[+] Get ip: "+hosts['ip_str'])
                    fwrite.write(hosts['ip_str']+'\n')
                    fwrite.flush()
        else:
            print("[!] No icon find.")
    except Exception:
        print("[!] Invalid API key")
    except KeyboardInterrupt:
        print("[*] Shutting down...")


def main():
    parser = argparse.ArgumentParser(
        description='Get ip list which using the same favicon.ico from shodan')
    parser.add_argument("-u", "--url", metavar='url',
                        help="the favicon.ico website url,example:http://www.baidu.com/", required=True)
    passargs = parser.parse_args()
    queryshodan(passargs.url)


if __name__ == '__main__':
    fwrite = open('IPS.txt','w')
    print(LOGO)
    main()
    fwrite.close()
