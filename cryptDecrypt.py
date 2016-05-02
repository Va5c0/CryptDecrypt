#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
import os
import urllib2
import urllib
import binascii
from passlib.hash import lmhash
from bs4 import BeautifulSoup
import re
import time


class colors:
    FAIL = '\033[91m'
    GREEN = '\033[32m'
    INFO = '\033[93m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def clean():
    if os.name == "nt":
        os.system("cls")
    else:
        os.system('tput reset')


def check_file(file):
    if os.path.exists(file):
        return True
    else:
        return False


def banner():
    clean()
    print (colors.GREEN + "         _\|/_" + """
         (o o)\n""" + colors.ENDC + "+-----" + colors.GREEN + "oOO" + colors.ENDC + "-" + colors.GREEN + "{_}" + colors.ENDC + "-" + colors.GREEN + "OOo" + colors.ENDC + """----------------------------------------------+
|   _____ _____ _____ ____ _____ ____ _____                    |
|  |   __|   | |  ___| __ |_   _| __ |_   _| _______ _______   |
|  |   __| | | | |___|    |_| |_|  __| | |  |  _____|  ___  |  |
|  |_____|_|___|_____|_|\_\_____|_|    |_|  | |_____| |___| |  |
|   ____ _____ _____ ____ _____ ____ _____  |  _____|      _|  |
|  |  _ \   __|  ___| __ |_   _| __ |_   _| | |_____|  |\  \   |
|  | |_| |  __| |___|    |_| |_|  __| | |   |_______|__| \__\  |
|  |____/_____|_____|_|\_\_____|_|    |_|                      |
|    """ + colors.GREEN + "v1.0" + "                                            by vasco" + colors.ENDC + "  | """"
+--------------------------------------------------------------+""")


def menu():
    print(colors.INFO + "\t\t>> Type " + colors.GREEN + "help" + colors.INFO + " to view commands <<" + colors.ENDC)
    print("+--------------------------------------------------------------+")

algthms_list = ["md2", "md4", "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "ntlm", "lm", "ntlm", "gost"]


def md5OnDecrypt(hashs):
    website = 'http://md5decryption.com/'
    weburl = urllib.urlencode({'hash': hashs, 'submit': 'Decrypt+It!'})
    req = urllib2.Request(website)
    try:
        fd = urllib2.urlopen(req, weburl)
        data = fd.read()
        match = re.search(r'(Decrypted Text: </b>)(.+[^>])(</font><br/><center>)', data)
        if match:
            print(colors.GREEN + " [i]" + colors.INFO + " Site: " + colors.ENDC + website + colors.INFO + "\t\t Password: " + colors.GREEN + (match.group(2)) + colors.ENDC)
        else:
            print(colors.FAIL + " [!]" + colors.INFO + " Site: " + colors.ENDC + website + colors.INFO + "\t\t Password: " + colors.FAIL + "Not found" + colors.ENDC)
    except urllib2.URLError:
        print(" [!]" + colors.INFO + " Site: " + colors.ENDC + website + colors.FAIL + "\t\tError: seems to be down" + colors.ENDC)


def md5OnDecrypt2(hashs):
    website = "http://www.md5.net/md5-cracker/"
    weburl = urllib.urlencode({"generator[hash]": hashs, "generator[submit]": "Submit"})
    req = urllib2.Request(website)
    try:
        fd = urllib2.urlopen(req, weburl)
        data = fd.read()
        match = re.search(r'(<p>)(.+)(</p>)', data)
        if match:
            print(colors.GREEN + " [i]" + colors.INFO + " Site: " + colors.ENDC + website + colors.INFO + "\t Password: " + colors.GREEN + (match.group(2)) + colors.ENDC)
        else:
            print(colors.FAIL + " [!]" + colors.INFO + " Site: " + colors.ENDC + website + colors.INFO + "\t Password: " + colors.FAIL + "Not found" + colors.ENDC)
    except urllib2.URLError:
        print(" [!]" + colors.INFO + " Site: " + colors.ENDC + website + colors.FAIL + "\t\tError: seems to be down" + colors.ENDC)


def md5OnDecrypt3(hashs):
    website = 'http://md5.gromweb.com/?md5=' + hashs
    req = urllib2.Request(website)
    try:
        fd = urllib2.urlopen(req)
        data = fd.read()
        match = re.search(r'(<em class="long-content string">)(.+)(</em></p>)', data)
        if match:
            print(colors.GREEN + " [i]" + colors.INFO + " Site: " + colors.ENDC + website[:23] + colors.INFO + "\t\t Password: " + colors.GREEN + (match.group(2)) + colors.ENDC)
        else:
            print(colors.FAIL + " [!]" + colors.INFO + " Site: " + colors.ENDC + website[:23] + colors.INFO + "\t\t Password: " + colors.FAIL + "Not found" + colors.ENDC)
    except urllib2.URLError:
        print(" [!]" + colors.INFO + " Site: " + colors.ENDC + website + colors.FAIL + "\t\tError: seems to be down" + colors.ENDC)


def md5OnDecrypt4(hashs):
    website = 'http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php'
    weburl = urllib.urlencode({'md5': hashs, 'image': 'go >>>'})
    req = urllib2.Request(website)
    try:
        fd = urllib2.urlopen(req, weburl)
        data = fd.read()
        match = re.search(r'(Hashed string</span>: )(.+)(</div>)', data)
        if match:
            print(colors.GREEN + " [i]" + colors.INFO + " Site: " + colors.ENDC + website[:23] + colors.INFO + "\t\t Password: " + colors.GREEN + (match.group(2)) + colors.ENDC)
        else:
            print(colors.FAIL + " [!]" + colors.INFO + " Site: " + colors.ENDC + website[:23] + colors.INFO + "\t\t Password: " + colors.FAIL + "Not found" + colors.ENDC)
    except urllib2.URLError:
        print(" [!]" + colors.INFO + " Site: " + colors.ENDC + website + colors.FAIL + "\t\tError: seems to be down" + colors.ENDC)


def md5OnDecrypt5(hashs):
    website = 'http://md5pass.info/'
    weburl = urllib.urlencode({'hash': hashs, 'get_pass': 'Get Pass'})
    req = urllib2.Request(website)
    try:
        fd = urllib2.urlopen(req, weburl)
        data = fd.read()
        match = re.search(r'(Password - <b>)(.+)(</b>)', data)
        if match:
            print(colors.GREEN + " [i]" + colors.INFO + " Site: " + colors.ENDC + website + colors.INFO + "\t\t\t Password: " + colors.GREEN + (match.group(2)) + colors.ENDC)
        else:
            print(colors.FAIL + " [!]" + colors.INFO + " Site: " + colors.ENDC + website + colors.INFO + "\t\t\t Password: " + colors.FAIL + "Not found" + colors.ENDC)
    except urllib2.URLError:
        print(" [!]" + colors.INFO + " Site: " + colors.ENDC + website + colors.FAIL + "\t\tError: seems to be down" + colors.ENDC)


def MultiOnDecrypt(hashs, web):
    website = 'http://md5decrypt.net/en/' + web
    weburl = urllib.urlencode({'hash': hashs, 'decrypt': 'Decrypt'})
    req = urllib2.Request(website)
    try:
        fd = urllib2.urlopen(req, weburl)
        data = fd.read()
        match = re.search(r'( : <b>)(.+)(</b><br/><br/>Found)', data)
        if match:
            print(colors.GREEN + " [i]" + colors.INFO + " Site: " + colors.ENDC + website + colors.INFO + "\t\t Password: " + colors.GREEN + (match.group(2)) + colors.ENDC)
        else:
            print(colors.FAIL + " [!]" + colors.INFO + " Site: " + colors.ENDC + website + colors.INFO + "\t\t Password: " + colors.FAIL + "Not found" + colors.ENDC)
    except urllib2.URLError:
        print(" [!]" + colors.INFO + " Site: " + colors.ENDC + website + colors.FAIL + "\t\tError: seems to be down" + colors.ENDC)


def MultiOnCrypt(word, algorithm):
    website = 'http://www.onlinehashcrack.com/hash-generator.php'
    weburl = urllib.urlencode({'strToHash': word, 'submit': 'Submit'})
    req = urllib2.Request(website)
    algorithm = algorithm.upper()
    try:
        fd = urllib2.urlopen(req, weburl)
        data = fd.read()
        match = re.search(r'(<h3 class="panel-title">)(.+)(</h3></div><div class="panel-body">)(.+)( </div></div>)', data)
        if match:
            bs = BeautifulSoup(data, "lxml")
            algthms = bs.find_all("div", "panel-success")
            for line in algthms:
                if ("class=\"panel-title\">" + algorithm) in str(line):
                    line = str(line).split("><")[4]
                    hashs = str(line).split(">")[1][:-6]
                    print(colors.GREEN + "\n\t [i]" + colors.INFO + " Hash: " + colors.GREEN + hashs + colors.ENDC)
        else:
            print(colors.FAIL + "\n\t [!]" + colors.INFO + " Hash: " + colors.FAIL + "Not found" + colors.ENDC)
    except urllib2.URLError:
        print(" [!]" + colors.INFO + " Site: " + colors.ENDC + website + colors.FAIL + "\t\tError: seems to be down" + colors.ENDC)


def md5OffDecryptFile(hashs, wordlist):
    try:
        if check_file(wordlist):
            with open(wordlist) as wordlistfile:
                for line in wordlistfile:
                    algorithm = hashlib.md5()
                    line = line.replace("\n", "")
                    algorithm.update(line)
                    wordlistdecrypted = algorithm.hexdigest()
                    if wordlistdecrypted == hashs:
                        print("\n\t [+]" + colors.INFO + " Hash Found: " + colors.GREEN + line + colors.ENDC)
        else:
            print (colors.FAIL + colors.BOLD + "\n[!] Dicctionary not found!!" + colors.ENDC)
    except:
        print(colors.BOLD + colors.FAIL + "\n\t[!] Error \n" + colors.ENDC)


def md4OffDecryptFile(hashs, wordlist):
    try:
        if check_file(wordlist):
            with open(wordlist) as wordlistfile:
                for line in wordlistfile:
                    algorithm = hashlib.md4()
                    line = line.replace("\n", "")
                    algorithm.update(line)
                    wordlistdecrypted = algorithm.hexdigest()
                    if wordlistdecrypted == hashs:
                        print("\n\t [+]" + colors.INFO + " Hash Found: " + colors.GREEN + line + colors.ENDC)
        else:
            print (colors.FAIL + colors.BOLD + "\n[!] Dicctionary not found!!" + colors.ENDC)
    except:
        print(colors.BOLD + colors.FAIL + "\n\t[!] Error \n" + colors.ENDC)


def sha1OffDecryptFile(hashs, wordlist):
    try:
        if check_file(wordlist):
            with open(wordlist) as wordlistfile:
                for line in wordlistfile:
                    algorithm = hashlib.sha1()
                    line = line.replace("\n", "")
                    algorithm.update(line)
                    wordlistdecrypted = algorithm.hexdigest()
                    if wordlistdecrypted == hashs:
                        print("\n\t [+]" + colors.INFO + " Hash Found: " + colors.GREEN + line + colors.ENDC)
        else:
            print (colors.FAIL + colors.BOLD + "\n[!] Dicctionary not found!!" + colors.ENDC)
    except:
        print(colors.BOLD + colors.FAIL + "\n\t[!] Error \n" + colors.ENDC)


def sha224OffDecryptFile(hashs, wordlist):
    try:
        if check_file(wordlist):
            with open(wordlist) as wordlistfile:
                for line in wordlistfile:
                    algorithm = hashlib.sha224()
                    line = line.replace("\n", "")
                    algorithm.update(line)
                    wordlistdecrypted = algorithm.hexdigest()
                    if wordlistdecrypted == hashs:
                        print("\n\t [+]" + colors.INFO + " Hash Found: " + colors.GREEN + line + colors.ENDC)
        else:
            print (colors.FAIL + colors.BOLD + "\n[!] Dicctionary not found!!" + colors.ENDC)
    except:
        print(colors.BOLD + colors.FAIL + "\n\t[!] Error \n" + colors.ENDC)


def sha256OffDecryptFile(hashs, wordlist):
    try:
        if check_file(wordlist):
            with open(wordlist) as wordlistfile:
                for line in wordlistfile:
                    algorithm = hashlib.sha256()
                    line = line.replace("\n", "")
                    algorithm.update(line)
                    wordlistdecrypted = algorithm.hexdigest()
                    if wordlistdecrypted == hashs:
                        print("\n\t [+]" + colors.INFO + " Hash Found: " + colors.GREEN + line + colors.ENDC)
        else:
            print (colors.FAIL + colors.BOLD + "\n[!] Dicctionary not found!!" + colors.ENDC)
    except:
        print(colors.BOLD + colors.FAIL + "\n\t[!] Error \n" + colors.ENDC)


def sha384OffDecryptFile(hashs, wordlist):
    try:
        if check_file(wordlist):
            with open(wordlist) as wordlistfile:
                for line in wordlistfile:
                    algorithm = hashlib.sha384()
                    line = line.replace("\n", "")
                    algorithm.update(line)
                    wordlistdecrypted = algorithm.hexdigest()
                    if wordlistdecrypted == hashs:
                        print("\n\t [+]" + colors.INFO + " Hash Found: " + colors.GREEN + line + colors.ENDC)
        else:
            print (colors.FAIL + colors.BOLD + "\n[!] Dicctionary not found!!" + colors.ENDC)
    except:
        print(colors.BOLD + colors.FAIL + "\n\t[!] Error \n" + colors.ENDC)


def sha512OffDecryptFile(hashs, wordlist):
    try:
        if check_file(wordlist):
            with open(wordlist) as wordlistfile:
                for line in wordlistfile:
                    algorithm = hashlib.sha512()
                    line = line.replace("\n", "")
                    algorithm.update(line)
                    wordlistdecrypted = algorithm.hexdigest()
                    if wordlistdecrypted == hashs:
                        print("\n\t [+]" + colors.INFO + " Hash Found: " + colors.GREEN + line + colors.ENDC)
        else:
            print (colors.FAIL + colors.BOLD + "\n[!] Dicctionary not found!!" + colors.ENDC)
    except:
        print(colors.BOLD + colors.FAIL + "\n\t[!] Error \n" + colors.ENDC)


def lmOffDecryptFile(hashs, wordlist):
    try:
        if check_file(wordlist):
            with open(wordlist) as wordlistfile:
                for line in wordlistfile:
                    line = line.replace("\n", "")
                    wordencrypted = lmhash.encrypt(line).upper()
                    if wordencrypted == hashs:
                        print("\n\t [+]" + colors.INFO + " Hash Found: " + colors.GREEN + line + colors.ENDC)
        else:
            print (colors.FAIL + colors.BOLD + "\n[!] Dicctionary not found!!" + colors.ENDC)
    except:
        print(colors.BOLD + colors.FAIL + "\n\t[!] Error \n" + colors.ENDC)


def router_pass(router):
    website = 'http://www.routerpasswords.com/'
    headers = ("Model", "Protocol", "Username", "Password")
    weburl = urllib.urlencode({'router': router, 'findpassword': 'Find Password'})
    req = urllib2.Request(website)
    try:
        fd = urllib2.urlopen(req, weburl)
        data = fd.read()
        match = re.search(r'(<td><b>)(.+)(</b></td>)', data)
        if match:
            bs = BeautifulSoup(data, "lxml")
            info = bs.find_all('td')
            i = 0
            for key in info:
                key = str(key).split("<td>")[1]
                if "<i>" in key:
                    model = key.split("<")[0]
                    rev = key.split("<i>")[1][:-9]
                    key = model + " -" + rev
                else:
                    key = key.split("<")[0]
                if key != "":
                    print(" [+] " + colors.INFO + headers[i] + ": " + colors.ENDC + key)
                    i += 1
                    if i == 4:
                        print("\n")
                        i = 0
        else:
            print (colors.FAIL + colors.BOLD + "\n[!] Router not found!!" + colors.ENDC)
    except urllib2.URLError:
        print (colors.FAIL + colors.BOLD + "\n[!] Web be down!!" + colors.ENDC)


def pass_gen():
    phrase = raw_input("\n [?]" + colors.INFO + " Writte a phrase: " + colors.ENDC)
    num_letras = raw_input("\n [?]" + colors.INFO + " Number of letters to catch every word: " + colors.ENDC)
    simbolos = raw_input("\n [?]" + colors.INFO + " Writte 2 symbols(separated by a space): " + colors.ENDC)
    simb1 = simbolos.split(" ")[0]
    simb2 = simbolos.split(" ")[1]

    phrase = phrase.lower()
    words = phrase.split(" ")
    anio = time.strftime("%Y")
    passwd = ""
    upperpass = ""

    for x in words:
        passwd += x[:int(num_letras)]

    for x in passwd:
        if passwd.index(x) % 2 == 0:
            x = x.upper()
        upperpass += x

    final = simb1 + str(anio[:2]) + upperpass + str(anio[2:]) + simb2
    print (colors.FAIL + "\n\tPASSWORD: " + colors.GREEN + final + colors.ENDC)


def router_list():
    try:
        contents = urllib.urlopen("http://www.routerpasswords.com/")
        bs = BeautifulSoup(contents, "lxml")
        routers = bs.find_all("option")
        routers_list = []
        i = 0
        y = 15
        x = 3
        print("\n")
        for router in routers:
            router = str(router).split(">")[1][:-8]
            routers_list.append(router)
        for router in sorted(routers_list, key=len):
            print router + "\t",
            i += 1
            if i == y:
                print "\n"
                i = 0
                x += 1
                if x == 15: y = 8
                if x == 28: y = 6
    except:
        print (colors.FAIL + colors.BOLD + "\n[!] Web be down!!" + colors.ENDC)
    finally:
        raw_input("\npress enter to continue...")


while True:
    banner()
    menu()

    optionMenu = raw_input(colors.GREEN + "\n  >>> " + colors.ENDC)

    if optionMenu == "help" or optionMenu == "HELP":
        banner()
        print(colors.INFO + "\t\t >> Available commands <<" + colors.ENDC)
        print("+--------------------------------------------------------------+")
        print("""
    Command            Description
    -------            -----------
    crypt_on           Online encrypter. Supports several algorithms
    crypt_off          Offline encrypter. Supports MD5 and SHA1

    decrypt_on         Online decrypter. MD5 and SHA1 supported
    decrypt_off        Offline decrypter. Only supports MD5 algorithm

    router_passwd      Search user/pass of a router for his mark
    router_list        List of routers available

    pass_gen           Generate a hard password

    exit               Exit of the script

    REQUIRED MODULES
    ----------------
    hashlib        urllib2        urllib
    binascii       passlib        bs4
    time           os
        """)
        raw_input("\npress enter to continue...")

    elif optionMenu == "crypt_off" or optionMenu == "CRYPT_OFF":  # OFFLINE ENCRYPTER
        banner()
        print(colors.INFO + "\t\t >> Offline Encrypter <<" + colors.ENDC)
        print("+--------------------------------------------------------------+")
        print("\n [+] " + colors.INFO + "List of algorithms available:" + colors.ENDC)
        print("\n\t [-] " + colors.GREEN + "MD4" + colors.ENDC + "\t[-] " + colors.GREEN + "SHA1" + colors.ENDC)
        print("\n\t [-] " + colors.GREEN + "MD5" + colors.ENDC + "\t[-] " + colors.GREEN + "SHA256" + colors.ENDC)
        print("\n\t [-] " + colors.GREEN + "NTLM" + colors.ENDC + "\t[-] " + colors.GREEN + "SHA384" + colors.ENDC)
        print("\n\t [-] " + colors.GREEN + "LM " + colors.ENDC + "\t[-] " + colors.GREEN + "SHA512" + colors.ENDC)
        option = raw_input("\n TYPE >> ")
        if option.lower() in algthms_list:
            word = raw_input("\n [?]" + colors.INFO + " Word to encrypt: " + colors.ENDC)
            if option == "md5" or option == "MD5":
                encrypted = hashlib.md5(word).hexdigest()
                print("\n\t [+]" + colors.INFO + " Hash: " + colors.GREEN + encrypted + colors.ENDC)
            elif option == "md4" or option == "MD4":
                encrypted = hashlib.md4(word).hexdigest()
                print("\n\t [+]" + colors.INFO + " Hash: " + colors.GREEN + encrypted + colors.ENDC)
            elif option == "sha1" or option == "SHA1":
                encrypted = hashlib.sha1(word).hexdigest()
                print("\n\t [+]" + colors.INFO + " Hash: " + colors.GREEN + encrypted.upper() + colors.ENDC)
            elif option == "sha224" or option == "SHA224":
                encrypted = hashlib.sha224(word).hexdigest()
                print("\n\t [+]" + colors.INFO + " Hash: " + colors.GREEN + encrypted.upper() + colors.ENDC)
            elif option == "sha256" or option == "SHA256":
                encrypted = hashlib.sha256(word).hexdigest()
                print("\n\t [+]" + colors.INFO + " Hash: " + colors.GREEN + encrypted.upper() + colors.ENDC)
            elif option == "sha384" or option == "SHA384":
                encrypted = hashlib.sha384(word).hexdigest()
                print("\n\t [+]" + colors.INFO + " Hash: " + colors.GREEN + encrypted.upper() + colors.ENDC)
            elif option == "sha512" or option == "SHA512":
                encrypted = hashlib.sha512(word).hexdigest()
                print("\n\t [+]" + colors.INFO + " Hash: " + colors.GREEN + encrypted.upper() + colors.ENDC)
            elif option == "ntlm" or option == "NTLM":
                hashs = hashlib.new("md4", word.encode("utf-16le")).digest()
                print("\n\t [+]" + colors.INFO + " Hash: " + colors.GREEN + binascii.hexlify(hashs).upper() + colors.ENDC)
            elif option == "lm" or option == "LM":
                hashs = lmhash.encrypt(word).upper()
                print("\n\t [+]" + colors.INFO + " Hash: " + colors.GREEN + hashs + colors.ENDC)
            else:
                pass
        else:
            print (colors.FAIL + colors.BOLD + "\n[!] Incorrect algorithm!!" + colors.ENDC)
        raw_input("\npress enter to continue...")

    elif optionMenu == "crypt_on" or optionMenu == "CRYPT_ON":  # ONLINE ENCRYPTER
        banner()
        print(colors.INFO + "\t\t >> Online Encrypter <<" + colors.ENDC)
        print("+--------------------------------------------------------------+")
        print("\n [+] " + colors.INFO + "List of algorithms available:" + colors.ENDC)
        print("\n\t [-] " + colors.GREEN + "MD2" + colors.ENDC + "\t[-] " + colors.GREEN + "SHA1" + colors.ENDC)
        print("\n\t [-] " + colors.GREEN + "MD4" + colors.ENDC + "\t[-] " + colors.GREEN + "SHA256" + colors.ENDC)
        print("\n\t [-] " + colors.GREEN + "MD5" + colors.ENDC + "\t[-] " + colors.GREEN + "SHA384" + colors.ENDC)
        print("\n\t [-] " + colors.GREEN + "NTLM" + colors.ENDC + "\t[-] " + colors.GREEN + "SHA512" + colors.ENDC)
        print("\n\t [-] " + colors.GREEN + "LM " + colors.ENDC + "\t[-] " + colors.GREEN + "GOST" + colors.ENDC)

        algorithm = raw_input("\n [?]" + colors.INFO + " Algorithm >> " + colors.ENDC)
        if algorithm.lower() in algthms_list:
            word = raw_input("\n [?]" + colors.INFO + " Word to encrypt: " + colors.ENDC)
            MultiOnCrypt(word, algorithm)
        else:
            print (colors.FAIL + colors.BOLD + "\n[!] Algorithm not found!!" + colors.ENDC)
        raw_input("\npress enter to continue...")

    elif optionMenu == "decrypt_on" or optionMenu == "DECRYPT_ON":  # ONLINE DECRYPTER
        banner()
        print(colors.INFO + "\t\t >> Online Decrypter <<" + colors.ENDC)
        print("+--------------------------------------------------------------+")
        print("\n [+] " + colors.INFO + "List of algorithms available:" + colors.ENDC)
        print("\n\t [-] " + colors.GREEN + "SHA1 " + colors.ENDC + "\t[-] " + colors.GREEN + "MD4" + colors.ENDC)
        print("\n\t [-] " + colors.GREEN + "SHA256" + colors.ENDC + "\t[-] " + colors.GREEN + "MD5" + colors.ENDC)
        print("\n\t [-] " + colors.GREEN + "SHA384" + colors.ENDC + "\t[-] " + colors.GREEN + "NTLM" + colors.ENDC)
        print("\n\t [-] " + colors.GREEN + "SHA512" + colors.ENDC)
        option = raw_input("\n TYPE >> ")
        if option.lower() in algthms_list:
            hashs = raw_input("\n [?]" + colors.INFO + " Hash to decrypt: " + colors.ENDC)
            if option == "md5" or option == "MD5":
                web = ""
                md5OnDecrypt(hashs)
                md5OnDecrypt2(hashs)
                md5OnDecrypt3(hashs)
                md5OnDecrypt4(hashs)
                md5OnDecrypt5(hashs)
                MultiOnDecrypt(hashs, web)
            elif option == "md4" or option == "MD4":
                web = "Md4/"
                MultiOnDecrypt(hashs, web)
            elif option == "sha1" or option == "SHA1":
                web = "Sha1/"
                MultiOnDecrypt(hashs, web)
            elif option == "sha256" or option == "SHA256":
                web = "Sha256/"
                MultiOnDecrypt(hashs, web)
            elif option == "sha384" or option == "SHA384":
                web = "Sha384/"
                MultiOnDecrypt(hashs, web)
            elif option == "sha512" or option == "SHA512":
                web = "Sha512/"
                MultiOnDecrypt(hashs, web)
            elif option == "ntlm" or option == "NTLM":
                web = "Ntlm/"
                MultiOnDecrypt(hashs, web)
            else:
                pass
        else:
            print (colors.FAIL + colors.BOLD + "\n[!] Incorrect algorithm!!" + colors.ENDC)
        raw_input("\npress enter to continue...")

    elif optionMenu == "decrypt_off" or optionMenu == "DECRYPT_OFF": # OFFLINE DECRYPTER
        banner()
        print(colors.INFO + "\t\t >> Offline Decrypter <<" + colors.ENDC)
        print("+--------------------------------------------------------------+")
        print("\n [+] " + colors.INFO + "List of algorithms available:" + colors.ENDC)
        print("\n\t [-] " + colors.GREEN + "MD4" + colors.ENDC + "\t[-] " + colors.GREEN + "SHA224" + colors.ENDC)
        print("\n\t [-] " + colors.GREEN + "MD5" + colors.ENDC + "\t[-] " + colors.GREEN + "SHA256" + colors.ENDC)
        print("\n\t [-] " + colors.GREEN + "LM " + colors.ENDC + "\t[-] " + colors.GREEN + "SHA384" + colors.ENDC)
        print("\n\t [-] " + colors.GREEN + "SHA1" + colors.ENDC + "\t[-] " + colors.GREEN + "SHA512" + colors.ENDC)
        option = raw_input("\n TYPE >> ")
        if option.lower() in algthms_list:
            hashs = raw_input("\n [?]" + colors.INFO + " Hash to decrypt: " + colors.ENDC)
            wordlist = raw_input("\n [?]" + colors.INFO + " Dictionary to use: " + colors.ENDC)
            if option == "md4" or option == "MD4":
                md4OffDecryptFile(hashs, wordlist)
            elif option == "md5" or option == "MD5":
                md5OffDecryptFile(hashs, wordlist)
            elif option == "sha1" or option == "SHA1":
                sha1OffDecryptFile(hashs, wordlist)
            elif option == "sha224" or option == "SHA224":
                sha224OffDecryptFile(hashs, wordlist)
            elif option == "sha256" or option == "SHA1":
                sha256OffDecryptFile(hashs, wordlist)
            elif option == "sha384" or option == "SHA384":
                sha384OffDecryptFile(hashs, wordlist)
            elif option == "sha512" or option == "SHA512":
                sha512OffDecryptFile(hashs, wordlist)
            elif option == "lm" or option == "LM":
                lmOffDecryptFile(hashs, wordlist)
            else:
                pass
        else:
            print (colors.FAIL + colors.BOLD + "\n[!] Incorrect algorithm!!" + colors.ENDC)
        raw_input("\npress enter to continue...")

    elif optionMenu == "router_passwd" or optionMenu == "ROUTER_PASSWD":  # SEARCH ROUTER USER/PASS
        option = "s"
        while option == "s" or option == "S":
            banner()
            print(colors.INFO + "\t\t >> Search passwords routers <<" + colors.ENDC)
            print("+--------------------------------------------------------------+")
            router = raw_input("\n [?]" + colors.INFO + " Router mark: " + colors.ENDC)
            router_pass(router)
            option = raw_input("\n [?]" + colors.INFO + " Search other?(s/n): " + colors.ENDC)
            if option == "s" or option == "S":
                option = "s"
            else:
                break

    elif optionMenu == "router_list" or optionMenu == "ROUTER_LIST":  # SHOW ROUTER LIST
        banner()
        print(colors.INFO + "\t\t >> List of routers available <<" + colors.ENDC)
        print("+--------------------------------------------------------------+")
        router_list()

    elif optionMenu == "pass_gen" or optionMenu == "PASS_GEN":  # GENERATE A HARD PASSWORD
        option = "s"
        while option == "s" or option == "S":
            banner()
            print(colors.INFO + "\t\t >> Hard password generator <<" + colors.ENDC)
            print("+--------------------------------------------------------------+")
            pass_gen()
            option = raw_input("\n [?]" + colors.INFO + " Generate another password (s/n): " + colors.ENDC)
            if option == "s" or option == "S":
                option = "s"
            else:
                break

    elif optionMenu == "exit" or optionMenu == "EXIT":  # EXIT
        clean()
        print "\tScript written by " + colors.BOLD + "Vasco" + colors.ENDC
        print "\nContact:"
        print colors.INFO + "Web: " + colors.ENDC + "http://fwhibbit.github.io/"
        print colors.INFO + "Blog: " + colors.ENDC + "http://fwhibbit.blogspot.com.es/"
        print colors.INFO + "Twitter: " + colors.ENDC + "@_v45c0\n"
        break
    else:
        print (colors.FAIL + colors.BOLD + "\n[!] Incorrect Option!!" + colors.ENDC)
        raw_input("\npress enter to continue...")