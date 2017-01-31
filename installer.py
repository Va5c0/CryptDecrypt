#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import os


class color:
    INFO = '\033[93m'
    ENDC = '\033[0m'
    GREEN = '\033[1;32m'


opt = raw_input("\n [?]" + color.INFO + "Instalar librerias necesarias(s/n): " + color.ENDC)
if opt.lower() == "s":
    print("\n [+]" + color.INFO + " Instalando librerias... \n" + color.ENDC)
    os.system('sudo pip install urllib3 passlib argparse')
    os.system('sudo easy_install hashlib')
    print("\n [+]" + color.GREEN + " Librerias instaladas!!\n" + color.ENDC)
    raw_input("presiona enter para continuar")
else:
    exit