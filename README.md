# Crypt - Decrypt Tool
Encrypt your password or decrypt your hash. Multiple algorithms supported:
- MD5
- NTLM
- LM
- SHA1
- SHA224
- SHA256
- SHA384
- SHA512

# How it work
Cloning this repo to your computer typing on your terminal:<br/>
<code>git clone https://github.com/Va5c0/CryptDecrypt.git</code>

Install necesary libraries:<br/>
<code>python installer.py</code>


Type <code>./crypt-decrypt.py -h</code> to see help.<br/>
Type <code>./crypt-decrypt.py</code> to see examples.<br/>

Use examples:

1- Encrypt word/s<br/>
<code>./crypt-decrypt.py -e -t [hash type] -w [word/s]</code>

2- Encrypt word/s with all hash types<br/>
<code>./crypt-decrypt.py -e -a -w [word/s]</code>

3- Decrypt hash (Online mode)<br/>
<code>./crypt-decrypt.py -d -o -t [hash type] -w [hash]</code>

4- Decrypt hash (Offline mode)<br/>
<code>./crypt-decrypt.py -d -f -t [hash type] -l [wordlist] -w [hash]</code>

5- Decrypt hashes contains in a file (Offline mode)<br/>
<code>./crypt-decrypt.py -d -f -t [hash type] -l [wordlist] -F [file with hashes list]</code>

6- Decrypt hashes contains in a file (Online mode)<br/>
<code>./crypt-decrypt.py -d -o -t [hash type] -F [file with hashes list]</code>

7- Identify type of hash<br/>
<code>./crypt-decrypt.py -i -w [hash]</code>

# Version
Crypt - Decrypt Tool V2.0
