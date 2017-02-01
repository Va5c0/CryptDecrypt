#!/usr/bin/env python
# -*- coding: utf-8 -*-


from argparse import ArgumentParser
import urllib2
import urllib
import re
import os
import commands

import hashlib
from passlib.hash import lmhash
import binascii


class colors:
    FAIL = '\033[91m'
    GREEN = '\033[32m'
    INFO = '\033[93m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def check_file(file):
    if os.path.exists(file):
        return True
    else:
        return False


def md5OnDecrypt(hashs):
    website = 'http://md5decryption.com/'
    weburl = urllib.urlencode({'hash': hashs, 'submit': 'Decrypt+It!'})
    req = urllib2.Request(website)
    try:
        fd = urllib2.urlopen(req, weburl)
        data = fd.read()
        match = re.search(r'(Decrypted Text: </b>)(.+[^>])(</font><br/><center>)', data)
        if match:
            print(colors.GREEN + " [i]" + colors.INFO + " Site: " + colors.ENDC + website + colors.INFO + "\t\t\t Password: " + colors.GREEN + (match.group(2)) + colors.ENDC)
        else:
            print(colors.FAIL + " [!]" + colors.INFO + " Site: " + colors.ENDC + website + colors.INFO + "\t\t\t Password: " + colors.FAIL + "Not found" + colors.ENDC)
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
            print(colors.GREEN + " [i]" + colors.INFO + " Site: " + colors.ENDC + website[:23] + colors.INFO + "\t\t\t Password: " + colors.GREEN + (match.group(2)) + colors.ENDC)
        else:
            print(colors.FAIL + " [!]" + colors.INFO + " Site: " + colors.ENDC + website[:23] + colors.INFO + "\t\t\t Password: " + colors.FAIL + "Not found" + colors.ENDC)
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
            print(colors.GREEN + " [i]" + colors.INFO + " Site: " + colors.ENDC + website[:23] + colors.INFO + "\t\t\t Password: " + colors.GREEN + (match.group(2)) + colors.ENDC)
        else:
            print(colors.FAIL + " [!]" + colors.INFO + " Site: " + colors.ENDC + website[:23] + colors.INFO + "\t\t\t Password: " + colors.FAIL + "Not found" + colors.ENDC)
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


def MultiOnDecrypt2(hashs):
    website = 'http://hashtoolkit.com/reverse-hash?hash=' + hashs
    req = urllib2.Request(website, headers={'User-Agent': 'Browser'})
    try:
        fd = urllib2.urlopen(req)
        data = fd.read()
        match = re.search(r'(<span title="decrypted .+ hash">)(.+)(</span>)', data)
        if match:
            print(colors.GREEN + " [i]" + colors.INFO + " Site: " + colors.ENDC + website.split('?')[0] + colors.INFO + "\t\t Password: " + colors.GREEN + (match.group(2)) + colors.ENDC)
        else:
            print(colors.FAIL + " [!]" + colors.INFO + " Site: " + colors.ENDC + website.split('?')[0] + colors.INFO + "\t\t Password: " + colors.FAIL + "Not found" + colors.ENDC)
    except urllib2.URLError:
        print(" [!]" + colors.INFO + " Site: " + colors.ENDC + website.split('?')[0] + colors.FAIL + "\t\tError: seems to be down" + colors.ENDC)


def MultiOnDecrypt3(hashs):
    website = 'https://hashdecryption.com/decrypt.php?str=' + hashs
    req = urllib2.Request(website, headers={'User-Agent': 'Browser'})
    try:
        fd = urllib2.urlopen(req)
        data = fd.read()
        match = re.search(r'(</b> is <b>)(.+)(</b><br>)', data)
        if match:
            print(colors.GREEN + " [i]" + colors.INFO + " Site: " + colors.ENDC + website.split('?')[0] + colors.INFO + "\t Password: " + colors.GREEN + (match.group(2)) + colors.ENDC)
        else:
            print(colors.FAIL + " [!]" + colors.INFO + " Site: " + colors.ENDC + website.split('?')[0] + colors.INFO + "\t Password: " + colors.FAIL + "Not found" + colors.ENDC)
    except urllib2.URLError:
        print(" [!]" + colors.INFO + " Site: " + colors.ENDC + website.split('?')[0] + colors.FAIL + "\t\tError: seems to be down" + colors.ENDC)


def MultiOffDecrypt(hashs, wordlist, htype):
    try:
        if check_file(wordlist):
            with open(wordlist) as wordlistfile:
                for line in wordlistfile:
                    if htype == "md5":
                        algorithm = hashlib.md5()
                    elif htype == "sha1":
                        algorithm = hashlib.sha1()
                    elif htype == "sha224":
                        algorithm = hashlib.sha224()
                    elif htype == "sha256":
                        algorithm = hashlib.sha256()
                    elif htype == "sha384":
                        algorithm = hashlib.sha384()
                    elif htype == "sha512":
                        algorithm = hashlib.sha512()
                    else:
                        print(colors.FAIL + colors.BOLD + "\n[!] Error hash type!!" + colors.ENDC)
                    line = line.replace("\n", "")
                    algorithm.update(line)
                    wordlistdecrypted = algorithm.hexdigest()
                    if wordlistdecrypted == hashs:
                        print(colors.GREEN + " [i]" + colors.INFO + " Password: " + colors.GREEN + line + colors.ENDC + "\n")
        else:
            print(colors.FAIL + colors.BOLD + "\n[!] Dicctionary not found!!" + colors.ENDC)
    except Exception, e:
        print(colors.BOLD + colors.FAIL + "\n [!] Error: " + colors.ENDC + str(e))


def lmOffDecryptFile(hashs, wordlist):
    try:
        if check_file(wordlist):
            with open(wordlist) as wordlistfile:
                for line in wordlistfile:
                    line = line.replace("\n", "")
                    wordencrypted = lmhash.encrypt(line).upper()
                    if wordencrypted == hashs:
                        print(colors.GREEN + " [i]" + colors.INFO + " Password: " + colors.GREEN + line + colors.ENDC + "\n")
        else:
            print (colors.FAIL + colors.BOLD + "\n[!] Dicctionary not found!!" + colors.ENDC)
    except Exception, e:
        print(colors.BOLD + colors.FAIL + "\n [!] Error: " + colors.ENDC + str(e))


VERSION = "2.0"

SAMPLES = """
Type ./crypt-decrypt.py -h to show help

Types of hashes supported
    - MD5        - SHA224
    - NTLM       - SHA256
    - LM         - SHA384
    - SHA1       - SHA512


Command line examples:

    1- Encrypt word/s
    ./crypt-decrypt.py -e -t <hash type> -w <word/s>

    2- Encrypt word/s with all hash types
    ./crypt-decrypt.py -e -a -w <word/s>

    3- Decrypt hash (Online mode)
    ./crypt-decrypt.py -d -o -t <hash type> -w <hash>

    4- Decrypt hash (Offline mode)
    ./crypt-decrypt.py -d -f -t <hash type> -l <wordlist> -w <hash>

    5- Decrypt hashes contains in a file (Offline mode)
    ./crypt-decrypt.py -d -f -t <hash type> -l <wordlist> -F <file with hashes list>

    6- Decrypt hashes contains in a file (Online mode)
    ./crypt-decrypt.py -d -o -t <hash type> -F <file with hashes list>

    7- Identify type of hash
    ./crypt-decrypt.py -i -w <hash>

    8- Identify type of hashes contains in a file
    ./crypt-decrypt.py -i -F <file with hashes list>

    """


def main():
    argp = ArgumentParser(
            description="Crypt - Decrypt Tool",
            usage="./crypt-decrypt.py [options] [-w word/hash] \nSamples: ./crypt-decrypt.py",
            version="Crypt - Decrypt Tool v" + VERSION)

    argp.add_argument('-e', '--encrypt', dest='encrypt', action='store_true',
                      help='Encrypt word/s (offline mode)')

    argp.add_argument('-d', '--decrypt', dest='decrypt', action='store_true',
                      help='Decrypt a hash')

    argp.add_argument('-i', '--identify', dest='identify', action='store_true',
                      help='Identify type of hash')

    argp.add_argument('-t', '--hash-type', dest='type',
                      help='Hash type to encrypt/decrypt word/hash')

    argp.add_argument('-w', '--word', dest='word',
                      help='Word or hash to encrypt/decrypt/identify')

    argp.add_argument('-o', '--online', dest='online', action='store_true',
                      help='Decrypt online mode')

    argp.add_argument('-f', '--offline', dest='offline', action='store_true',
                      help='Decrypt offline mode')

    argp.add_argument('-l', '--wordlist', dest='wordlist',
                      help='Dictionary to decrypt hash (offline mode only)')

    argp.add_argument('-a', '--all', dest='all', action='store_true',
                      help='Encrypt word/s with all hash types')

    argp.add_argument('-F', '--file', dest='file',
                      help='File with hashes to decrypt/identify')

    args = argp.parse_args()

    if args.encrypt and not args.all and not args.decrypt and not args.identify:  # ENCRYPTER
        alg = args.type.lower()
        word = args.word
        print("\n [+]" + colors.INFO + " Word: " + colors.ENDC + word)
        print(" [+]" + colors.INFO + " Type: " + colors.ENDC + alg)
        if alg == "md5":
            encrypted = hashlib.md5(word).hexdigest()
            print(colors.GREEN + "   [i]" + colors.INFO + " Hash: " + colors.GREEN + encrypted + colors.ENDC + "\n")
        elif alg == "sha1":
            encrypted = hashlib.sha1(word).hexdigest()
            print(colors.GREEN + "   [i]" + colors.INFO + " Hash: " + colors.GREEN + encrypted + colors.ENDC + "\n")
        elif alg == "sha224":
            encrypted = hashlib.sha224(word).hexdigest()
            print(colors.GREEN + "   [i]" + colors.INFO + " Hash: " + colors.GREEN + encrypted + colors.ENDC + "\n")
        elif alg == "sha256":
            encrypted = hashlib.sha256(word).hexdigest()
            print(colors.GREEN + "   [i]" + colors.INFO + " Hash: " + colors.GREEN + encrypted + colors.ENDC + "\n")
        elif alg == "sha384":
            encrypted = hashlib.sha384(word).hexdigest()
            print(colors.GREEN + "   [i]" + colors.INFO + " Hash: " + colors.GREEN + encrypted + colors.ENDC + "\n")
        elif alg == "sha512":
            encrypted = hashlib.sha512(word).hexdigest()
            print(colors.GREEN + "   [i]" + colors.INFO + " Hash: " + colors.GREEN + encrypted + colors.ENDC + "\n")
        elif alg == "ntlm":
            encrypted = hashlib.new("md4", word.encode("utf-16le")).digest()
            print(colors.GREEN + "   [i]" + colors.INFO + " Hash: " + colors.GREEN + binascii.hexlify(encrypted).upper() + colors.ENDC + "\n")
        elif alg == "lm":
            encrypted = lmhash.encrypt(word).upper()
            print(colors.GREEN + "   [i]" + colors.INFO + " Hash: " + colors.GREEN + encrypted + colors.ENDC + "\n")
        else:
            print (colors.FAIL + colors.BOLD + "\n[!] Incorrect algorithm!!\n" + colors.ENDC)

    elif args.encrypt and args.all and not args.decrypt and not args.identify:  # ALL TYPES
        word = args.word
        print("\n [+]" + colors.INFO + " Word: " + colors.ENDC + word)
        print("\n [+]" + colors.INFO + " Type: " + colors.ENDC + "md5")
        print(colors.GREEN + "   [i]" + colors.INFO + " Hash: " + colors.GREEN + hashlib.md5(word).hexdigest() + colors.ENDC)
        print("\n [+]" + colors.INFO + " Type: " + colors.ENDC + "sha1")
        print(colors.GREEN + "   [i]" + colors.INFO + " Hash: " + colors.GREEN + hashlib.sha1(word).hexdigest() + colors.ENDC)
        print("\n [+]" + colors.INFO + " Type: " + colors.ENDC + "sha224")
        print(colors.GREEN + "   [i]" + colors.INFO + " Hash: " + colors.GREEN + hashlib.sha224(word).hexdigest() + colors.ENDC)
        print("\n [+]" + colors.INFO + " Type: " + colors.ENDC + "sha256")
        print(colors.GREEN + "   [i]" + colors.INFO + " Hash: " + colors.GREEN + hashlib.sha256(word).hexdigest() + colors.ENDC)
        print("\n [+]" + colors.INFO + " Type: " + colors.ENDC + "sha384")
        print(colors.GREEN + "   [i]" + colors.INFO + " Hash: " + colors.GREEN + hashlib.sha384(word).hexdigest() + colors.ENDC)
        print("\n [+]" + colors.INFO + " Type: " + colors.ENDC + "sha512")
        print(colors.GREEN + "   [i]" + colors.INFO + " Hash: " + colors.GREEN + hashlib.sha512(word).hexdigest() + colors.ENDC)
        print("\n [+]" + colors.INFO + " Type: " + colors.ENDC + "lm")
        print(colors.GREEN + "   [i]" + colors.INFO + " Hash: " + colors.GREEN + lmhash.encrypt(word).upper() + colors.ENDC)
        print("\n [+]" + colors.INFO + " Type: " + colors.ENDC + "ntlm")
        encrypted = hashlib.new("md4", word.encode("utf-16le")).digest()
        print(colors.GREEN + "   [i]" + colors.INFO + " Hash: " + colors.GREEN + binascii.hexlify(encrypted).upper() + colors.ENDC)

    elif args.decrypt and not args.encrypt and not args.identify and not args.file:  # DECRYPTER
        alg = args.type.lower()
        hashs = args.word
        if args.online and not args.offline:  # Online
            print("\n [+]" + colors.INFO + " Hash: " + colors.ENDC + hashs)
            print(" [+]" + colors.INFO + " Type: " + colors.ENDC + alg)
            if alg == "md5":
                md5OnDecrypt(hashs)
                md5OnDecrypt3(hashs)
                md5OnDecrypt4(hashs)
                MultiOnDecrypt2(hashs)
                MultiOnDecrypt3(hashs)
            elif alg == "sha1":
                MultiOnDecrypt2(hashs)
                MultiOnDecrypt3(hashs)
            elif alg == "sha224":
                MultiOnDecrypt3(hashs)
            elif alg == "sha256":
                web = "Sha256/"
                MultiOnDecrypt(hashs, web)
                MultiOnDecrypt2(hashs)
                MultiOnDecrypt3(hashs)
            elif alg == "sha384":
                web = "Sha384/"
                MultiOnDecrypt(hashs, web)
                MultiOnDecrypt2(hashs)
                MultiOnDecrypt3(hashs)
            elif alg == "sha512":
                web = "Sha512/"
                MultiOnDecrypt(hashs, web)
                MultiOnDecrypt2(hashs)
                MultiOnDecrypt3(hashs)
            elif alg == "ntlm":
                web = "Ntlm/"
                MultiOnDecrypt(hashs, web)
            elif alg == "lm":
                print(colors.FAIL + colors.BOLD + "\n[!] Hash type not supported in this mode" + colors.ENDC + "\n")
            else:
                print (colors.FAIL + colors.BOLD + "\n[!] Incorrect algorithm!!" + colors.ENDC)

        elif args.offline and not args.online:  # Offline
            print("\n [+]" + colors.INFO + " Hash: " + colors.ENDC + hashs)
            print(" [+]" + colors.INFO + " Type: " + colors.ENDC + alg)
            if alg == "md5":
                MultiOffDecrypt(hashs, args.wordlist, "md5")
            elif alg == "sha1":
                MultiOffDecrypt(hashs, args.wordlist, "sha1")
            elif alg == "sha224":
                MultiOffDecrypt(hashs, args.wordlist, "sha224")
            elif alg == "sha256":
                MultiOffDecrypt(hashs, args.wordlist, "sha256")
            elif alg == "sha384":
                MultiOffDecrypt(hashs, args.wordlist, "sha384")
            elif alg == "sha512":
                MultiOffDecrypt(hashs, args.wordlist, "sha512")
            elif alg == "ntlm":
                print(colors.FAIL + colors.BOLD + "\n[!] Hash type not supported in this mode" + colors.ENDC + "\n")
            elif alg == "lm":
                lmOffDecryptFile(hashs, args.wordlist)
            else:
                print (colors.FAIL + colors.BOLD + "\n[!] Incorrect algorithm!!" + colors.ENDC)

    elif args.identify and not args.encrypt and not args.decrypt:  # IDENTIFIER
        if args.file:
            with open(args.file, 'r') as f:
                for h in f.readlines():
                    print("\n [+]" + colors.INFO + " Hash: " + colors.GREEN + h.strip("\n") + colors.ENDC)
                    r = commands.getoutput('./hash-identifier.py %s' % h.strip('\n'))
                    for x in r.split("\n"):
                        if not "Least Possible" in x:
                            print(x + "\n"),
                        else:
                            break
        else:
            r = commands.getoutput('./hash-identifier.py %s' % args.word)
            print(r)

    elif args.file and args.decrypt and not args.encrypt and not args.identify:  # FILE
        alg = args.type
        with open(args.file, 'r') as myfile:
            if args.online:  # Online
                for line in myfile.readlines():
                    if alg == "md5":
                        md5OnDecrypt(line)
                        md5OnDecrypt3(line)
                        md5OnDecrypt4(line)
                        MultiOnDecrypt2(line)
                        MultiOnDecrypt3(line)
                    elif alg == "sha1":
                        MultiOnDecrypt2(line)
                        MultiOnDecrypt3(line)
                    elif alg == "sha224":
                        MultiOnDecrypt3(line)
                    elif alg == "sha256":
                        web = "Sha256/"
                        MultiOnDecrypt(line, web)
                        MultiOnDecrypt2(line)
                        MultiOnDecrypt3(line)
                    elif alg == "sha384":
                        web = "Sha384/"
                        MultiOnDecrypt(line, web)
                        MultiOnDecrypt2(line)
                        MultiOnDecrypt3(line)
                    elif alg == "sha512":
                        web = "Sha512/"
                        MultiOnDecrypt(line, web)
                        MultiOnDecrypt2(line)
                        MultiOnDecrypt3(line)
                    elif alg == "ntlm":
                        web = "Ntlm/"
                        MultiOnDecrypt(line, web)
                    elif alg == "lm":
                        print(colors.FAIL + colors.BOLD + "\n[!] Hash type not supported in this mode" + colors.ENDC + "\n")
                    else:
                        print (colors.FAIL + colors.BOLD + "\n[!] Incorrect algorithm!!" + colors.ENDC)

            elif args.offline:  # Offline
                for line in myfile.readlines():
                    line = line.strip("\n")
                    print("\n [+]" + colors.INFO + " Hash: " + colors.ENDC + line)
                    print(" [+]" + colors.INFO + " Type: " + colors.ENDC + args.type)
                    if alg == "md5":
                        MultiOffDecrypt(line, args.wordlist, "md5")
                    elif alg == "sha1":
                        MultiOffDecrypt(line, args.wordlist, "sha1")
                    elif alg == "sha224":
                        MultiOffDecrypt(line, args.wordlist, "sha224")
                    elif alg == "sha256":
                        MultiOffDecrypt(line, args.wordlist, "sha256")
                    elif alg == "sha384":
                        MultiOffDecrypt(line, args.wordlist, "sha384")
                    elif alg == "sha512":
                        MultiOffDecrypt(line, args.wordlist, "sha512")
                    elif alg == "ntlm":
                        print(colors.FAIL + colors.BOLD + "\n[!] Hash type not supported in this mode" + colors.ENDC + "\n")
                    elif alg == "lm":
                        lmOffDecryptFile(line, args.wordlist)
                    else:
                        print (colors.FAIL + colors.BOLD + "\n[!] Incorrect algorithm!!" + colors.ENDC)

    else:
        print(SAMPLES)


if __name__ == "__main__":
    main()
