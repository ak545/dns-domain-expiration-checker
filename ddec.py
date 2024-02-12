#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Program: DNS Domain Expiration Checker from ak545
#
# Author of the original script: Matty < matty91 at gmail dot com >
# https://github.com/Matty9191
#
# Author of this fork: Andrey Klimov < ak545 at mail dot ru >
# https://github.com/ak545
#
# Thanks to:
# Carl Mercier (https://github.com/cmer)
# Leif (https://github.com/akhepcat)
# woodholly (https://github.com/woodholly)
#
# Current Version: 0.2.23
# Creation Date: 2019-07-05
# Date of last changes: 2024-02-12
#
# License:
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.

from __future__ import unicode_literals
from typing import List, Dict, Tuple, Optional, Any
import os
import sys
import platform
import argparse
import time
import json
from datetime import datetime
import difflib
import io
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
import subprocess

try:
    import requests
except ImportError:
    sys.exit(
        """You need requests!
                install it from http://pypi.python.org/pypi/requests
                or run 'pip install requests'"""
    )
try:
    import socks
except ImportError:
    sys.exit(
        """You need Socks!
                install it from http://pypi.python.org/pypi/PySocks
                or run 'pip install PySocks'
                or run 'pip install requests[socks]'"""
    )
try:
    import dateutil.parser
except ImportError:
    sys.exit(
        """You need python-dateutil!
                install it from http://pypi.python.org/pypi/python-dateutil
                or run 'pip install python-dateutil'"""
    )
try:
    import whois
except ImportError:
    sys.exit(
        """You need python-whois!
                install it from http://pypi.python.org/pypi/python-whois
                or run 'pip install python-whois'"""
    )
try:
    from colorama import init
    from colorama import Fore, Back, Style
except ImportError:
    sys.exit(
        """You need colorama!
                install it from http://pypi.python.org/pypi/colorama
                or run 'pip install colorama'"""
    )

# Init colorama
init(autoreset=True)

# Check Python Version
if sys.version_info < (3, 6):
    print('Error. Python version 3.6 or later required to run this script')
    print('Your version:', sys.version)
    sys.exit(-1)

# Global constants
__version__: str = '0.2.23'

FR: str = Fore.RESET

FW: str = Fore.WHITE
FG: str = Fore.GREEN
FRC: str = Fore.RED
FC: str = Fore.CYAN
FY: str = Fore.YELLOW
FM: str = Fore.MAGENTA
FB: str = Fore.BLUE
FBC: str = Fore.BLACK

FLW: str = Fore.LIGHTWHITE_EX
FLG: str = Fore.LIGHTGREEN_EX
FLR: str = Fore.LIGHTRED_EX
FLC: str = Fore.LIGHTCYAN_EX
FLY: str = Fore.LIGHTYELLOW_EX
FLM: str = Fore.LIGHTMAGENTA_EX
FLB: str = Fore.LIGHTBLUE_EX
FLBC: str = Fore.LIGHTBLACK_EX

BLB: str = Back.LIGHTBLACK_EX
BLR: str = Back.LIGHTRED_EX
BLC: str = Back.LIGHTCYAN_EX
BC: str = Back.CYAN
BLY: str = Back.LIGHTYELLOW_EX
BY: str = Back.YELLOW
BLW: str = Back.LIGHTWHITE_EX
BW: str = Back.WHITE
BR: str = Back.RESET

SDIM: str = Style.DIM
SNORMAL: str = Style.NORMAL
SBRIGHT: str = Style.BRIGHT
SR: str = Style.RESET_ALL

SEP: str = os.sep
pathname: str = os.path.dirname(os.path.abspath(__file__))

# Folder for storing the whois cache.
WHOIS_CACHE_PATH: str = pathname + SEP + 'ddec-cache' + SEP

# SMTP options
SMTP_SERVER: str = os.getenv('SMTP_SERVER', 'localhost')
SMTP_PORT: int = int(os.getenv('SMTP_PORT', '25'))

# SMTP_SERVER: str = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
# SMTP_PORT: int = int(os.getenv('SMTP_PORT', '587'))  # For starttls

# SMTP_SERVER: str = os.getenv('SMTP_SERVER', 'smtp.mail.ru')
# SMTP_PORT: int = int(os.getenv('SMTP_PORT', '25'))  # Default

# SMTP_SERVER: str = os.getenv('SMTP_SERVER', 'smtp.yandex.ru')
# SMTP_PORT: int = int(os.getenv('SMTP_PORT', '465'))  # For SSL

SMTP_SENDER: str = os.getenv('SMTP_SENDER', 'root')
SMTP_PASSWORD: str = os.getenv('SMTP_PASSWORD', 'P@ssw0rd')

# Telegram bot options
# Proxy for telegram
TELEGRAM_PROXIES: Dict = {}
# TELEGRAM_PROXIES: Dict = {
#     'http': 'socks5://127.0.0.1:9150',
#     'https': 'socks5://127.0.0.1:9150',
# }

# # Get help from https://core.telegram.org/bots
# # token that can be generated talking with @BotFather on telegram
TELEGRAM_TOKEN: str = '<INSERT YOUR TOKEN>'
#
# # channel id for telegram
TELEGRAM_CHAT_ID: str = '<INSERT YOUR CHANNEL ID>'
#
# # url for post request to api.telegram.org
TELEGRAM_URL: str = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/'

if str(os.getenv('SMTP_CHECK_SSL_HOSTNAME')) == '0':
    SMTP_CHECK_SSL_HOSTNAME: bool = False
else:
    SMTP_CHECK_SSL_HOSTNAME: bool = True

REQUEST_HEADERS: Dict = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                  'AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/122.0.0.0 Safari/537.36'
}

# Options for an external utility whois
# Keywords for whois-data
EXPIRE_STRINGS: Tuple = (
    'registry expiry date:',
    'expiration:',
    'domain expiration date:',
    'registrar registration expiration date:',
    'expire:',
    'expires:',
    'paid-till:',
    'option expiration date:',
    '[expires on]',
    'expiry date:',
    'expiration date:',
    'expiration time:',
    'renewal date:',
    'paid-till:',
    'domain expires:',
    'expires on:',
    'expires    on:',
    'valid until:',
    'registry expiry date:',
    '[有効期限]',
)
REGISTRAR_STRINGS: Tuple = (
    '[registrant]',
    'registrar:',
    'registrant:',
    # 'status:',
    'sponsoring registrar:',
)
WHOIS_SERVER_STRINGS: Tuple = (
    'registrar whois server:',
    'whois server:',
)
NOT_FOUND_STRINGS: Tuple = (
    'not found',
    'no match for domain',
    'not currently eligible for renewal',
    'no entries found for the selected source(s).',
)

# Unsupported domains (all lowercase !!!)
# this tuple contains fragments of word endings
UNSUPPORTED_DOMAINS: Tuple = (
    '.gov',
    'denic.de',
    '.eu',
    '.au',
)

# Command for external whois
if sys.platform == 'win32':
    WHOIS_COMMAND: str = f'{pathname}{SEP}winbin{SEP}whois-cygwin64{SEP}whois.exe'
    # WHOIS_COMMAND: str = f'{pathname}{SEP}winbin{SEP}whois-sysinternals{SEP}whois64.exe'
    # WHOIS_COMMAND: str = f'{pathname}{SEP}winbin{SEP}whois-nir-sofer{SEP}WhoisCL.exe'
else:
    WHOIS_COMMAND: str = 'whois'

# Timeout for external whois
WHOIS_COMMAND_TIMEOUT: int = 20

# The list of expired domains
EXPIRES_DOMAIN: Dict = {}

# The list of soon domains
SOON_DOMAIN: Dict = {}

# List of domains for which the WHOIS text has changed
WHOIS_TEXT_CHANGED_DOMAIN: Dict = {}

# The list of error domains
ERRORS_DOMAIN: Dict = {}  # Common errors
ERRORS2_DOMAIN: Dict = {}  # limit connection
FREE_DOMAINS: Dict = {}  # Free domains

# Command line parameters
CLI: Optional[Any] = None

# The number of days that are added to the expiration
# date of the domain registration
# in order to mark the expiration of the domain that
# is coming soon
G_SOON_ADD: int = 21

# List of domains processed from file
G_DOMAINS_LIST: List = []

# Currency symbol
# G_CURRENCY_SYMBOL: str = '₽'
G_CURRENCY_SYMBOL: str = '¥'
# G_CURRENCY_SYMBOL: str = '£'
# G_CURRENCY_SYMBOL: str = '€'
# G_CURRENCY_SYMBOL: str = '$'

# Counters:
# Total Domains
G_DOMAINS_TOTAL: int = 0

# Valid Domains
G_DOMAINS_VALID: int = 0

# Soon Domains
G_DOMAINS_SOON: int = 0

# The total price for the domains of this group
G_TOTAL_COST_SOON: int = 0

# Expired Domains
G_DOMAINS_EXPIRE: int = 0

# Free Domains
G_DOMAINS_FREE: int = 0

# The total price for the domains of this group
G_TOTAL_COST_EXPIRE: int = 0

# Error Domains
G_DOMAINS_ERROR: int = 0


def remove_control_characters_of_colorama(text: str) -> str:
    """
    Remove all colorama control characters from a string
    :param text: str
    :return: str
    """
    words: Tuple = (
        FR,

        FW,
        FG,
        FRC,
        FC,
        FY,
        FM,
        FB,
        FBC,

        FLW,
        FLG,
        FLR,
        FLC,
        FLY,
        FLM,
        FLB,
        FLBC,

        BLB,
        BLR,
        BLC,
        BC,
        BLY,
        BLW,
        BW,
        BR,

        SDIM,
        SNORMAL,
        SBRIGHT,
        SR,
    )
    for word in words:
        text = text.replace(word, '')
    return text


def save_whois_cache(file: str, json_data: Dict) -> None:
    """
    Save of the json whois data to json cache file
    :param file: str
    :param json_data: Dict
    :return: None
    """
    save_file: str = f'{WHOIS_CACHE_PATH}{file}'
    with io.open(save_file, 'w+', encoding='utf8', newline='\n') as f:
        json.dump(json_data, f, indent=4, ensure_ascii=False)


def load_whois_cache(file: str) -> Optional[Dict]:
    """
    Load of the json whois data from json cache file
    :param file: str
    :return: json Dict or None
    """
    json_data: Optional[Dict] = None
    saved_file: str = f'{WHOIS_CACHE_PATH}{file}'
    if os.path.exists(saved_file):
        with open(saved_file, 'r+', encoding='utf8') as f:
            try:
                json_data = json.load(f)
            except Exception as e:
                print(
                    f'{FLR}Error load file: {FLW}{saved_file}\n'
                    f'{FLR}{str(e)}'
                )
    return json_data


def compare_whois_text(f1: str, f2: str, domain: str = None) -> str:
    """
    Compare two whois text
    :param f1: str
    :param f2: str
    :param domain: str
    :return: str
    """
    f1_list: List = f1.splitlines(keepends=True)
    f2_list: List = f2.splitlines(keepends=True)
    f1_list_fixed: List = []
    f2_list_fixed: List = []
    for line1 in f1_list:
        f1_list_fixed.append(f'{line1.lower().strip()}\n')
    for line2 in f2_list:
        f2_list_fixed.append(f'{line2.lower().strip()}\n')

    diff: Optional[Any] = difflib.ndiff(f1_list_fixed, f2_list_fixed)

    # TODO: For future functionality
    # diff_html = difflib.HtmlDiff(tabsize=2)
    # with open(f'{domain}.html', 'w', encoding='utf-8') as fp:
    #     html = diff_html.make_file(
    #         fromlines=f1_list_fixed,
    #         tolines=f2_list_fixed,
    #         fromdesc='Original',
    #         todesc='Modified',
    #     )
    #     fp.write(html)

    delta: str = ''
    is_found: bool = False
    for x in diff:
        line_diff: str = x.lower().strip()
        if (
            'updated date:' in line_diff or
            '% timestamp:' in line_diff or
            'whois lookup made at ' in line_diff or
            'last update of whois ' in line_diff or
            'last updated on' in line_diff
        ):
            continue
        elif line_diff.startswith('- '):
            is_found = not is_found
            delta += f'{FRC}{x}'
        elif line_diff.startswith('+ '):
            is_found = not is_found
            delta += f'{FG}{x}'
        elif line_diff.startswith('? ') and is_found:
            is_found = False
            delta += f'{FC}{x}'
        # else:
        #     delta += f'{FLC}{x}'
        if delta != '':
            delta += f'{FR}'
    return delta


def whois_check() -> None:
    """
    External whois availability check
    :return: None
    """
    global WHOIS_COMMAND

    str_tmp: str = ""
    whois_found: bool = False
    if sys.platform == 'win32':
        delemiter: str = ';'
        s_path: str = 'Path'
    else:
        delemiter: str = ':'
        s_path: str = 'PATH'
    os_env_path = os.environ.get(s_path).split(delemiter)
    for item in os_env_path:
        str_tmp = item
        if str_tmp != '':
            if str_tmp[-1] != SEP:
                str_tmp += SEP
            str_tmp += 'whois'
            if sys.platform == 'win32':
                str_tmp += '.exe'
            if Path(str_tmp).is_file():
                whois_found = True
                break
    if whois_found:
        WHOIS_COMMAND = str_tmp
        if not CLI.no_banner:
            print(
                f'\tThe {FLG}whois{FR} found in: {FC}{str_tmp}'
            )
    else:
        print(f'\tThe {FLR}whois{FR} not found!')
        if sys.platform == 'win32':
            print(
                '\tPlease, install the cygwin from '
                'https://www.cygwin.com/ to c:\\cygwin64 (as sample)\n'
                '\tChoice in installer whois and install it.\n'
                '\tAfter it, add path to c:\\cygwin64\\bin to system PATH variable.\n'
            )
        elif sys.platform == 'linux':
            print(
                '\tPlease, install the whois\n\n'
                '\t\tFor Ubuntu/Debian:\n'
                '\t\t\tsudo apt update && sudo apt upgrade\n'
                '\t\t\tsudo apt install whois\n\n'

                '\t\tFor older RHEL/CentOS/Fedora\n'
                '\t\t\tand other older RPM-Based Linux:\n'
                '\t\t\tFor RHEL 6.x/CentOS 6.x:\n'
                '\t\t\t\tsudo yum install jwhois\n\n'

                '\t\t\tFor RHEL 7.x/CentOS 7.x/Fedora 22/Rocky Linux/Alma Linux\n'
                '\t\t\tand other RPM-Based Linux:\n'
                '\t\t\t\tsudo dnf install jwhois\n\n'

                '\t\tFor Arch/Manjaro:\n'
                '\t\t\tsudo pacman -S whois\n'
            )
        elif sys.platform == 'darwin':
            print(
                '\tPlease, install the whois\n'
                '\t\tbrew install whois\n'
                '\t\t(Homebrew: https://brew.sh)'
            )
    if not whois_found:
        sys.exit(-1)


def make_whois_query(domain: str, domain_group: str) -> Tuple:
    """
    Execute a external whois and parse the data to extract specific data
    :param domain: str
    :param domain_group: str
    :return: Tuple
    """
    global ERRORS_DOMAIN
    global G_DOMAINS_ERROR

    try:
        p = subprocess.Popen([WHOIS_COMMAND, domain],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except Exception as e:
        print(
            f'{FLR}Unable to Popen() the whois binary.\n'
            f'Domain: {domain}.\n'
            f'Exception: {e}')
        sys.exit(-1)

    try:
        whois_data = p.communicate(timeout=WHOIS_COMMAND_TIMEOUT)[0]
    except Exception as e:
        whois_data = str(e)

        tmp_list = []
        if ERRORS_DOMAIN.get(domain_group) is not None:
            tmp_list = ERRORS_DOMAIN[domain_group]
            if domain.lower() not in tmp_list:
                G_DOMAINS_ERROR += 1
                tmp_list.append(domain.lower())
                ERRORS_DOMAIN[domain_group] = tmp_list
        else:
            G_DOMAINS_ERROR += 1
            tmp_list.append(domain.lower())
            ERRORS_DOMAIN[domain_group] = tmp_list

        if 'timed out after' in whois_data.lower():
            return whois_data, None, None, None, 25
        elif 'failed to retrieve the whois record' in whois_data.lower():
            return whois_data, None, None, None, 26
        else:
            return None, None, None, None, 1

    # TODO: For future functionality
    # Work around whois issue #55 which returns a non-zero
    # exit code for valid domains.
    # if p.returncode != 0:
    #    print('The WHOIS utility exit()'ed with a non-zero return code')
    #    sys.exit(-1)

    whois_data = str(whois_data, 'utf-8', 'ignore')
    (
        r_w_data,
        r_expir_date,
        r_reg,
        r_w_server,
        r_error
    ) = parse_whois_data(domain=domain, domain_group=domain_group, whois_data=whois_data)
    if r_w_data is not None:
        whois_data = r_w_data

    return whois_data, r_expir_date, r_reg, r_w_server, r_error


def parse_whois_data(domain: str, domain_group: str, whois_data: str) -> Tuple:
    """
    Grab the registrar and expiration date from the WHOIS data
    :param domain: str
    :param domain_group: str
    :param whois_data: str
    :return: Tuple
    """
    global ERRORS2_DOMAIN

    raw_whois_data = None
    expiration_date = None
    registrar = None
    whois_server = None
    ret_error = None

    tmp_whois_data = whois_data.lower()

    sys.stdout = sys.__stdout__
    sys.stderr = sys.__stderr__
    # Init colorama again
    init(autoreset=True)

    if 'connection timed out' in tmp_whois_data:
        # Connection timed out
        ret_error = 25
        return raw_whois_data, None, None, None, ret_error
    elif 'failed to retrieve the whois record' in tmp_whois_data:
        # Failed to retrieve the WHOIS record of the specified domain
        ret_error = 26
        return raw_whois_data, None, None, None, ret_error
    elif (
            'no entries found for the selected source(s)' in tmp_whois_data
    ) or (
            'domain not found.' in tmp_whois_data
    ) or (
            'status: free' in tmp_whois_data
    ) or (
            f'no match for domain "{domain}"' in tmp_whois_data
    ):
        # It is Free!
        # print(f'{FC}{tmp_whois_data}')
        ret_error = 11
        return raw_whois_data, None, None, None, ret_error

    elif 'http://www.denic.de/en/domains/whois-service/web-whois.html' in tmp_whois_data:
        # denic.de
        ret_error = 22
        return raw_whois_data, None, None, None, ret_error

    elif 'https://www.dnc.org.nz/whois/search?domain_name=' in tmp_whois_data:
        # *.nz
        ret_error = 23
        return raw_whois_data, None, None, None, ret_error

    elif 'https://dnc.org.nz/enquiry-form/' in tmp_whois_data:
        # *.nz new version of this site
        ret_error = 231
        return raw_whois_data, None, None, None, ret_error

    elif 'the registration of this domain is restricted' in tmp_whois_data:
        # TODO: idiotic service where designated links don't exist
        # the registration of this domain is restricted,
        # as it is protected by the identity digital dpml brand protection policy.
        # additional information can be found at
        # https://www.identity.digital/what-we-do/brand-protection.
        ret_error = 24
        return raw_whois_data, None, None, None, ret_error

    elif 'https://whois.dot.ph/' in tmp_whois_data:
        # whois.dot.ph
        try:
            page = requests.get(
                f'https://whois.dot.ph/?utf8=%E2%9C%93&search={domain}',
                timeout=10,
                headers=REQUEST_HEADERS,
                verify=True,
            )
        except requests.exceptions.RequestException:
            ret_error = -1
            print(f'{FLR}Failed to fetch remote blocklist providers. Continue...')
            return raw_whois_data, None, None, None, ret_error

        html = page.content.decode('utf-8', 'ignore').lower()
        raw_whois_data = html
        if 'domain is available.' in html:
            ret_error = 11
            return raw_whois_data, None, None, None, ret_error

        elif 'var expirydate = moment(' in html:
            for line in html.splitlines():
                if 'var expirydate = moment(' in line:
                    if 'registrar:' in line:
                        registrar = line.replace(
                            'registrar:', ''
                        ).replace(
                            '<br>', ''
                        )

                    str_date = line.replace(
                        "var expirydate = moment('", ''
                    ).replace(
                        "').format('yyyy-mm-ddthh:mm:ss z');", ''
                    )
                    expiration_date = dateutil.parser.parse(
                        str_date, ignoretz=True)
                    break

    elif 'www.dominios.es' in tmp_whois_data:
        # whois.nic.es
        try:
            page = requests.get(
                f'https://www.iana.org/whois?q={domain}',
                timeout=10,
                headers=REQUEST_HEADERS,
                verify=True,
            )
        except requests.exceptions.RequestException:
            ret_error = -1
            print(f'{FLR}Failed to fetch remote blocklist providers. Continue...')
            return raw_whois_data, None, None, None, ret_error

        html = page.content.decode('utf-8', 'ignore').lower()
        raw_whois_data = html
        if 'status:       active' in html:
            ret_error = 232
            for line in html.splitlines():
                if 'changed: ' in line:
                    str_date = line.replace(
                        'changed:', ''
                    ).strip()
                    expiration_date = dateutil.parser.parse(
                        str_date, ignoretz=True)
                elif 'whois: ' in line:
                    whois_server = line.replace(
                        'whois:', ''
                    ).strip()
                elif 'organisation: ' in line:
                    registrar = line.replace(
                        'organisation:', ''
                    ).strip()
            return raw_whois_data, expiration_date, registrar, whois_server, ret_error

    else:
        raw_whois_data = tmp_whois_data
        for line in tmp_whois_data.splitlines():
            if line.strip() == '':
                continue

            if 'your connection limit exceeded. please slow down and try again later.' in line:
                # Interval is small
                ret_error = 2

                tmp_list = []
                if ERRORS2_DOMAIN.get(domain_group) is not None:
                    tmp_list = ERRORS2_DOMAIN[domain_group]
                    if domain.lower() not in tmp_list:
                        tmp_list.append(domain.lower())
                        ERRORS2_DOMAIN[domain_group] = tmp_list
                else:
                    tmp_list.append(domain.lower())
                    ERRORS2_DOMAIN[domain_group] = tmp_list

                return raw_whois_data, None, None, None, ret_error

            if any(not_found_string in line for not_found_string in NOT_FOUND_STRINGS):
                # Is it Free?
                return raw_whois_data, None, None, None, ret_error

            if any(expire_string in line for expire_string in EXPIRE_STRINGS):
                if not expiration_date:
                    try:
                        str_date = line.partition(': ')[2]
                        if str_date == '':
                            str_date = line.partition(']')[2]
                        str_date = str_date.replace('/', '-')
                        expiration_date = dateutil.parser.parse(
                            str_date, ignoretz=True)
                    except Exception:
                        ret_error = 1

            if any(registrar_string in line for registrar_string in REGISTRAR_STRINGS):
                if not registrar:
                    registrar = line.partition(': ')[2].strip()

            if any(whois_server_string in line for whois_server_string in
                   WHOIS_SERVER_STRINGS):
                if not whois_server:
                    whois_server = line.partition(': ')[2].strip()

    return raw_whois_data, expiration_date, registrar, whois_server, ret_error


def calculate_expiration_days(expiration_date: datetime) -> int:
    """
    Check to see when a domain will expire
    :param expiration_date: datetime
    :return: int
    """
    try:
        domain_expire = expiration_date - datetime.now()
    except Exception as e:
        print(f'{FLR}Unable to calculate the expiration days.\nError: {str(e)}')
        sys.exit(-1)

    return domain_expire.days


def make_report_for_telegram() -> None:
    """
    Make report for send through the Telegram bot.
    :return: None
    """
    g_total_cost: int = G_TOTAL_COST_SOON + G_TOTAL_COST_EXPIRE

    if (
            len(EXPIRES_DOMAIN) == 0 and
            len(SOON_DOMAIN) == 0 and
            len(ERRORS_DOMAIN) == 0 and
            len(ERRORS2_DOMAIN) == 0 and
            len(FREE_DOMAINS) == 0 and
            len(WHOIS_TEXT_CHANGED_DOMAIN) == 0
    ):
        return None

    today: str = f'{datetime.now():%d.%m.%Y %H:%M}'
    hl: str = f'{"-" * 42}'
    message: str = ''
    message += f'<b>Domains Report  [ {today} ]</b>\n'

    if len(EXPIRES_DOMAIN) > 0:
        # add expiring domains
        message += '\n<b>Domains are expiring</b><pre>'
        message += f'\n{hl}   DL\n'
        group_i: int = 0
        i: int = 0
        for group, list_of_dict_data in EXPIRES_DOMAIN.items():
            group_i += 1
            s_g_cr: str = '\n' if group_i > 1 else ''
            if group != '/':
                str_domain_item: str = f'\n{s_g_cr}{group_i:>4}. {group}\n\n'
                message += str_domain_item
            for item_dict_data in list_of_dict_data:
                for domain, day_left in item_dict_data.items():
                    i += 1
                    dn: str = f'{domain:<37}'
                    str_domain_item: str = f'{i:>5}. {dn} {day_left}\n'
                    message += str_domain_item
        message += '</pre>'

    if len(SOON_DOMAIN) > 0:
        # add soon domains
        message += '\n\n<b>Domains are expiring soon</b><pre>'
        message += f'\n{hl}   DL\n'
        group_i: int = 0
        i: int = 0
        for group, list_of_dict_data in SOON_DOMAIN.items():
            group_i += 1
            s_g_cr: str = '\n' if group_i > 1 else ''
            if group != '/':
                str_domain_item: str = f'\n{s_g_cr}{group_i:>4}. {group}\n\n'
                message += str_domain_item
            for item_dict_data in list_of_dict_data:
                for domain, day_left in item_dict_data.items():
                    i += 1
                    dn: str = f'{domain:<37}'
                    str_domain_item: str = f'{i:>5}. {dn} {day_left}\n'
                    message += str_domain_item
        message += '</pre>'

    if len(ERRORS_DOMAIN) > 0:
        # add error domains
        message += '\n\n<b>Domains that caused errors</b><pre>'
        message += f'\n{hl}\n'
        group_i: int = 0
        i: int = 0
        for group, list_of_domains in ERRORS_DOMAIN.items():
            group_i += 1
            s_g_cr: str = '\n' if group_i > 1 else ''
            if group != '/':
                str_domain_item: str = f'\n{s_g_cr}{group_i:>4}. {group}\n\n'
                message += str_domain_item
            for domain in list_of_domains:
                i += 1
                dn: str = f'{domain:<37}'
                str_domain_item: str = f'{i:>5}. {dn}\n'
                message += str_domain_item
        message += '</pre>'

    if len(ERRORS2_DOMAIN) > 0:
        # add error2 domains
        message += '\n\n<b>Exceeded the limit on whois</b><pre>'
        message += f'\n{hl}\n'
        group_i: int = 0
        i: int = 0
        for group, list_of_domains in ERRORS2_DOMAIN.items():
            group_i += 1
            s_g_cr: str = '\n' if group_i > 1 else ''
            if group != '/':
                str_domain_item: str = f'\n{s_g_cr}{group_i:>4}. {group}\n\n'
                message += str_domain_item
            for domain in list_of_domains:
                i += 1
                dn: str = f'{domain:<37}'
                str_domain_item: str = f'{i:>5}. {dn}\n'
                message += str_domain_item
        message += '</pre>'

    if len(FREE_DOMAINS) > 0:
        # add free domains
        message += '\n\n<b>Free domains</b><pre>'
        message += f'\n{hl}\n'
        group_i: int = 0
        i: int = 0
        for group, list_of_domains in FREE_DOMAINS.items():
            group_i += 1
            s_g_cr: str = '\n' if group_i > 1 else ''
            if group != '/':
                str_domain_item: str = f'\n{s_g_cr}{group_i:>4}. {group}\n\n'
                message += str_domain_item
            for domain in list_of_domains:
                i += 1
                dn: str = f'{domain:<37}'
                str_domain_item: str = f'{i:>5}. {dn}\n'
                message += str_domain_item
        message += '</pre>'

    if len(WHOIS_TEXT_CHANGED_DOMAIN) > 0:
        # add whois-text changed domains
        message += '\n\n<b>Domains whose whois text has changed</b><pre>'
        message += f'\n{hl}\n'
        group_i: int = 0
        i: int = 0
        for group, list_of_dict_data in WHOIS_TEXT_CHANGED_DOMAIN.items():
            group_i += 1
            s_g_cr: str = '\n' if group_i > 1 else ''
            if group != '/':
                str_domain_item: str = f'\n{s_g_cr}{group_i:>4}. {group}\n\n'
                message += str_domain_item
            for item_dict_data in list_of_dict_data:
                for domain, value in item_dict_data.items():
                    i += 1
                    dn: str = f'{domain:<20}'
                    txt: str = value.get('txt')
                    if CLI.trim_long_whois_text:
                        if len(txt) > 350:
                            dt: str = value.get('dt')
                            str_domain_item: str = (
                                f'{i:>5}. {dn}{dt}\n\n'
                                f'{txt[:350]}...\n\n'
                            )
                        else:
                            dt: str = value.get('dt')
                            str_domain_item: str = (
                                f'{i:>5}. {dn}{dt}\n\n'
                                f'{txt}\n\n'
                            )
                    else:
                        dt: str = value.get('dt')
                        str_domain_item: str = (
                            f'{i:>5}. {dn}{dt}\n\n'
                            f'{txt}\n\n'
                        )
                    message += str_domain_item
        message += '</pre>'

    if g_total_cost > 0:
        message += '\n\n<b>Cost</b><pre>'
        message += f'\n{hl}\n'
        if G_TOTAL_COST_EXPIRE > 0:
            message += (
                f'For Expires   : '
                f'{G_CURRENCY_SYMBOL} '
                f'{round(G_TOTAL_COST_EXPIRE, 2)}\n'
            )
        if G_TOTAL_COST_SOON > 0:
            message += (
                f'For Soon      : '
                f'{G_CURRENCY_SYMBOL} '
                f'{round(G_TOTAL_COST_SOON, 2)}\n'
            )
        message += f'{hl}\n'
        message += (
            f'Total         : '
            f'{G_CURRENCY_SYMBOL} '
            f'{round(g_total_cost, 2)}\n'
        )
        message += '</pre>'

    if len(message) <= 3800:  # 4086
        send_telegram(message)
    else:
        if not CLI.split_long_message:
            message = message[:3700]
            if not message.endswith('</pre>'):
                message += '</pre>'

            tmp_txt = ''
            if not CLI.trim_long_whois_text:
                tmp_txt = (
                    '<b>-trim</b>'
                    ' and/or '
                )
            message += (
                f'\n...\n'
                f'Message is too long!\n'
                f'Use '
                f'{tmp_txt}'
                f'<b>-split</b>'
                f' option'
            )
            if not CLI.trim_long_whois_text:
                message += 's'
            if CLI.email_to:
                message += ' or see full report in email'
            message += '\n'
            send_telegram(message)
        else:
            ii: int = 0
            iii: int = 0
            while True:
                ii += 1
                if ii == 1:
                    message_parts = message[:3800]
                else:
                    message_parts = f'# {ii}\n<pre>'
                    message_parts += message[:3800]

                message_parts = message_parts.rstrip('\n')
                if not message_parts.endswith('</pre>'):
                    message_parts += '</pre>'

                message = message[3800:]

                send_telegram(message_parts)

                if len(message) == 0:
                    break

                # For Telegram limits
                iii += 1
                if iii == 20:
                    iii = 0
                    time.sleep(40)
                else:
                    time.sleep(2)


def send_telegram(message: str) -> None:
    """
    Sending a message through the Telegram bot.
    :param message: str
    :return: None
    """
    params: Dict = {'chat_id': TELEGRAM_CHAT_ID, 'parse_mode': 'html', 'text': message}
    try:

        if len(TELEGRAM_PROXIES) > 0:
            r: Optional[Any] = requests.post(
                TELEGRAM_URL + 'sendMessage',
                timeout=10,
                data=params,
                proxies=TELEGRAM_PROXIES,
                headers=REQUEST_HEADERS,
                verify=True,
            )
        else:
            r: Optional[Any] = requests.post(
                TELEGRAM_URL + 'sendMessage',
                timeout=10,
                data=params,
                headers=REQUEST_HEADERS,
                verify=True,
            )

        if r is not None and r.status_code != 200:
            print(f'{FLR}{r.text}')

    except requests.exceptions.RequestException as e:
        print(f'{FRC}Error {str(e)}')


def make_report_for_email() -> None:
    """
    Make report for send through the email.
    :return: None
    """
    g_total_cost: int = G_TOTAL_COST_SOON + G_TOTAL_COST_EXPIRE

    if (
            len(EXPIRES_DOMAIN) == 0 and
            len(SOON_DOMAIN) == 0 and
            len(ERRORS_DOMAIN) == 0 and
            len(ERRORS2_DOMAIN) == 0 and
            len(FREE_DOMAINS) == 0 and
            len(WHOIS_TEXT_CHANGED_DOMAIN) == 0
    ):
        return

    email_to_list: List = []
    if ',' in CLI.email_to:
        tmp_list: List = CLI.email_to.split(',')
        for email in tmp_list:
            s_email: str = email.strip()
            if s_email != '':
                email_to_list.append(s_email)
    else:
        email_to_list = [CLI.email_to]

    for email_to in email_to_list:
        today: str = f'{datetime.now():%d.%m.%Y %H:%M}'
        msg = MIMEMultipart('alternative')
        msg['From'] = SMTP_SENDER
        msg['To'] = email_to
        subject: str = f'Domains Report  [ {today} ]'
        if CLI.email_subject:
            subject = subject + ': ' + CLI.email_subject
        msg['Subject'] = subject

        body_text: str = '%BODY%'
        '''
        font-family: Courier New,Courier,Lucida Sans Typewriter,Lucida Typewriter,monospace  !important; 
        padding: 50px; 
        margin: 50px; 
        color: $000 !important; 
        border-color: rgb(31, 31, 31) !important; 
        background-color: rgba(24,103,194,0.81); 
        '''
        body_html: str = """
        <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
        <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <style>
            a:link {  text-decoration: none  !important; color: #FFF  !important; }
            a:visited  {  text-decoration: none  !important; color: #FFF  !important; }
            a:hover {  text-decoration: none  !important; color: #F9E79F  !important; }
            a:active {  text-decoration: none  !important; color: #FFF  !important; }
        </style>
        </head>
        <html>
        
          <body marginwidth="0" marginheight="0" leftmargin="0" topmargin="0" 
          style="background-color:#333333;  
          font-family: Courier New,Courier,Lucida Sans Typewriter,Lucida Typewriter,monospace  !important;
          margin:0; 
          padding:0; 
          min-width: 100%; 
          -webkit-text-size-adjust:none; 
          -ms-text-size-adjust:none;">
          
            <div style="width: auto; 
            color:#FFFFFF; 
            border-color: #A80333 !important; 
            background-color: #C70039; 
            
            margin: 50px; 
            padding: 50px; 
            display: inline-block;">
            %BODY%
            </div>
            
          </body>
        
        </html>
        """

        hl: str = f'{"-" * 42}'

        # For part plain
        domain_list: str = ''
        domain_list += f'\n{subject}\n'

        if len(EXPIRES_DOMAIN) > 0:
            # add expiring domains
            domain_list += '\nDomains are expiring\n\n'
            domain_list += f'{hl}    DL\n'
            group_i: int = 0
            i: int = 0
            for group, list_of_dict_data in EXPIRES_DOMAIN.items():
                group_i += 1
                s_g_cr: str = '\n' if group_i > 1 else ''
                if group != '/':
                    str_domain_item: str = f'\n{s_g_cr}{group_i:>4}. {group}\n\n'
                    domain_list += str_domain_item
                for item_dict_data in list_of_dict_data:
                    for domain, day_left in item_dict_data.items():
                        i += 1
                        dn: str = f'{domain:<37}'
                        str_domain_item: str = f'{i:>5}. {dn} {day_left}\n'
                        domain_list += str_domain_item

        if len(SOON_DOMAIN) > 0:
            # add soon domains
            domain_list += '\nDomains are expiring soon\n\n'
            domain_list += f'{hl}    DL\n'
            group_i: int = 0
            i: int = 0
            for group, list_of_dict_data in SOON_DOMAIN.items():
                group_i += 1
                s_g_cr: str = '\n' if group_i > 1 else ''
                if group != '/':
                    str_domain_item: str = f'\n{s_g_cr}{group_i:>4}. {group}\n\n'
                    domain_list += str_domain_item
                for item_dict_data in list_of_dict_data:
                    for domain, day_left in item_dict_data.items():
                        i += 1
                        dn: str = f'{domain:<37}'
                        str_domain_item: str = f'{i:>5}. {dn} {day_left}\n'
                        domain_list += str_domain_item

        if len(ERRORS_DOMAIN) > 0:
            # add error domains
            domain_list += '\nDomains that caused errors\n\n'
            domain_list += f'{hl}\n'
            group_i: int = 0
            i: int = 0
            for group, list_of_domains in ERRORS_DOMAIN.items():
                group_i += 1
                s_g_cr: str = '\n' if group_i > 1 else ''
                if group != '/':
                    str_domain_item: str = f'\n{s_g_cr}{group_i:>4}. {group}\n\n'
                    domain_list += str_domain_item
                for domain in list_of_domains:
                    i += 1
                    dn: str = f'{domain:<37}'
                    str_domain_item: str = f'{i:>5}. {dn}\n'
                    domain_list += str_domain_item

        if len(ERRORS2_DOMAIN) > 0:
            # add error2 domains
            domain_list += '\nExceeded the limit on whois\n\n'
            domain_list += f'{hl}\n'
            group_i: int = 0
            i: int = 0
            for group, list_of_domains in ERRORS2_DOMAIN.items():
                group_i += 1
                s_g_cr: str = '\n' if group_i > 1 else ''
                if group != '/':
                    str_domain_item: str = f'\n{s_g_cr}{group_i:>4}. {group}\n\n'
                    domain_list += str_domain_item
                for domain in list_of_domains:
                    i += 1
                    dn: str = f'{domain:<37}'
                    str_domain_item: str = f'{i:>5}. {dn}\n'
                    domain_list += str_domain_item

        if len(FREE_DOMAINS) > 0:
            # add free domains
            domain_list += '\nFree domains\n\n'
            domain_list += f'{hl}\n'
            group_i: int = 0
            i: int = 0
            for group, list_of_domains in FREE_DOMAINS.items():
                group_i += 1
                s_g_cr: str = '\n' if group_i > 1 else ''
                if group != '/':
                    str_domain_item: str = f'\n{s_g_cr}{group_i:>4}. {group}\n\n'
                    domain_list += str_domain_item
                for domain in list_of_domains:
                    i += 1
                    dn: str = f'{domain:<37}'
                    str_domain_item: str = f'{i:>5}. {dn}\n'
                    domain_list += str_domain_item

        if len(WHOIS_TEXT_CHANGED_DOMAIN) > 0:
            # add whois-text changed domains
            domain_list += '\nDomains whose whois text has changed\n\n'
            domain_list += f'{hl}\n'
            group_i: int = 0
            i: int = 0
            for group, list_of_dict_data in WHOIS_TEXT_CHANGED_DOMAIN.items():
                group_i += 1
                s_g_cr: str = '\n' if group_i > 1 else ''
                if group != '/':
                    str_domain_item: str = f'\n{s_g_cr}{group_i:>4}. {group}\n\n'
                    domain_list += str_domain_item
                for item_dict_data in list_of_dict_data:
                    for domain, value in item_dict_data.items():
                        i += 1
                        dn: str = f'{domain:<20}'
                        txt: str = value.get('txt')
                        dt: str = value.get('dt')
                        str_domain_item: str = (
                            f'{i:>5}. {dn}{dt}\n\n'
                            f'{txt}\n\n'
                        )
                        domain_list += str_domain_item

        if g_total_cost > 0:
            domain_list += '\nCost\n'
            domain_list += f'{hl}\n'
            if G_TOTAL_COST_EXPIRE > 0:
                domain_list += (
                    f'For Expires   : '
                    f'{G_CURRENCY_SYMBOL} '
                    f'{round(G_TOTAL_COST_EXPIRE, 2)}\n'
                )
            if G_TOTAL_COST_SOON > 0:
                domain_list += (
                    f'For Soon      : '
                    f'{G_CURRENCY_SYMBOL} '
                    f'{round(G_TOTAL_COST_SOON, 2)}\n'
                )
            domain_list += f'{hl}\n'
            domain_list += (
                f'Total         : '
                f'{G_CURRENCY_SYMBOL} '
                f'{round(g_total_cost, 2)}\n'
            )
            domain_list += '\n'

        body_text = body_text.replace('%BODY%', domain_list)

        # For part html
        domain_list = f'<h3><b>{subject}</b></h3><br>\n'
        if len(EXPIRES_DOMAIN) > 0:
            # add expiring domains
            domain_list += (
                '<br><span style="color: #FFA500"><b>'
                'Domains are expiring'
                '</b></span><br>\n<pre>\n'
            )
            domain_list += f'{hl}    DL\n'
            group_i: int = 0
            i: int = 0
            for group, list_of_dict_data in EXPIRES_DOMAIN.items():
                group_i += 1
                s_g_cr: str = '\n' if group_i > 1 else ''
                if group != '/':
                    str_domain_item: str = (
                        f'\n{s_g_cr}'
                        f'<span style="color: #F9E79F"><b>'
                        f'{group_i:>4}. {group}'
                        f'</b></span>\n\n'
                    )
                    domain_list += str_domain_item
                for item_dict_data in list_of_dict_data:
                    for domain, day_left in item_dict_data.items():
                        i += 1
                        dn: str = f'{domain:<37}'
                        str_domain_item: str = f'{i:>5}. {dn} {day_left}\n'
                        domain_list += str_domain_item
            domain_list += '</pre>'

        if len(SOON_DOMAIN) > 0:
            # add soon domains
            domain_list += (
                '<br><span style="color: #FFA500"><b>'
                'Domains are expiring soon'
                '</b></span><br>\n<pre>\n'
            )
            domain_list += f'{hl}    DL\n'
            group_i: int = 0
            i: int = 0
            for group, list_of_dict_data in SOON_DOMAIN.items():
                group_i += 1
                s_g_cr: str = '\n' if group_i > 1 else ''
                if group != '/':
                    str_domain_item: str = (
                        f'\n{s_g_cr}'
                        f'<span style="color: #F9E79F"><b>'
                        f'{group_i:>4}. {group}'
                        f'</b></span>\n\n'
                    )
                    domain_list += str_domain_item
                for item_dict_data in list_of_dict_data:
                    for domain, day_left in item_dict_data.items():
                        i += 1
                        dn: str = f'{domain:<37}'
                        str_domain_item: str = f'{i:>5}. {dn} {day_left}\n'
                        domain_list += str_domain_item
            domain_list += '</pre>'

        if len(ERRORS_DOMAIN) > 0:
            # add error domains
            domain_list += (
                '<br><span style="color: #FFA500"><b>'
                'Domains that caused errors'
                '</b></span><br>\n<pre>\n'
            )
            domain_list += f'{hl}\n'
            group_i: int = 0
            i: int = 0
            for group, list_of_domains in ERRORS_DOMAIN.items():
                group_i += 1
                s_g_cr: str = '\n' if group_i > 1 else ''
                if group != '/':
                    str_domain_item: str = (
                        f'\n{s_g_cr}'
                        f'<span style="color: #F9E79F"><b>'
                        f'{group_i:>4}. {group}'
                        f'</b></span>\n\n'
                    )
                    domain_list += str_domain_item
                for domain in list_of_domains:
                    i += 1
                    dn: str = f'{domain:<37}'
                    str_domain_item: str = f'{i:>5}. {dn}\n'
                    domain_list += str_domain_item
            domain_list += '</pre>'

        if len(ERRORS2_DOMAIN) > 0:
            # add error2 domains
            domain_list += (
                '<br><span style="color: #FFA500"><b>'
                'Exceeded the limit on whois'
                '</b></span><br>\n<pre>\n'
            )
            domain_list += f'{hl}\n'
            group_i: int = 0
            i: int = 0
            for group, list_of_domains in ERRORS2_DOMAIN.items():
                group_i += 1
                s_g_cr: str = '\n' if group_i > 1 else ''
                if group != '/':
                    str_domain_item: str = (
                        f'\n{s_g_cr}'
                        f'<span style="color: #F9E79F"><b>'
                        f'{group_i:>4}. {group}'
                        f'</b></span>\n\n'
                    )
                    domain_list += str_domain_item
                for domain in list_of_domains:
                    i += 1
                    dn: str = f'{domain:<37}'
                    str_domain_item: str = f'{i:>5}. {dn}\n'
                    domain_list += str_domain_item
            domain_list += '</pre>'

        if len(FREE_DOMAINS) > 0:
            # add free domains
            domain_list += (
                '<br><span style="color: #FFA500"><b>'
                'Free domains'
                '</b></span><br>\n<pre>\n'
            )
            domain_list += f'{hl}\n'
            group_i: int = 0
            i: int = 0
            for group, list_of_domains in FREE_DOMAINS.items():
                group_i += 1
                s_g_cr: str = '\n' if group_i > 1 else ''
                if group != '/':
                    str_domain_item: str = (
                        f'\n{s_g_cr}'
                        f'<span style="color: #F9E79F"><b>'
                        f'{group_i:>4}. {group}'
                        f'</b></span>\n\n'
                    )
                    domain_list += str_domain_item
                for domain in list_of_domains:
                    i += 1
                    dn: str = f'{domain:<37}'
                    str_domain_item: str = f'{i:>5}. {dn}\n'
                    domain_list += str_domain_item
            domain_list += '</pre>'

        if len(WHOIS_TEXT_CHANGED_DOMAIN) > 0:
            # add whois-text changed domains
            domain_list += (
                '<br><span style="color: #FFA500"><b>'
                'Domains whose whois text has changed'
                '</b></span><br>\n<pre>\n'
            )
            domain_list += f'{hl}\n'
            group_i: int = 0
            i: int = 0
            for group, list_of_domains in WHOIS_TEXT_CHANGED_DOMAIN.items():
                group_i += 1
                s_g_cr: str = '\n' if group_i > 1 else ''
                if group != '/':
                    str_domain_item: str = (
                        f'\n{s_g_cr}'
                        f'<span style="color: #F9E79F"><b>'
                        f'{group_i:>4}. {group}'
                        f'</b></span>\n\n'
                    )
                    domain_list += str_domain_item
                for item_dict_data in list_of_domains:
                    for domain, value in item_dict_data.items():
                        i += 1
                        dn: str = f'{domain:<20}'
                        txt: str = value.get('txt')
                        dt: str = value.get('dt')
                        str_domain_item: str = (
                            f'<span style="color: #F9E79F"><b>'
                            f'{i:>5}. {dn}{dt}'
                            f'</b></span>\n\n'
                            f'{txt}\n\n'
                        )
                        domain_list += str_domain_item

            domain_list += '</pre>'

        if g_total_cost > 0:
            domain_list += (
                '<br>'
                '<span style="color: #FFA500"><b>'
                'Cost'
                '</b></span>'
                '<pre>\n'
            )
            domain_list += f'{hl}\n'
            if G_TOTAL_COST_EXPIRE > 0:
                domain_list += (
                    f'For Expires   : '
                    f'{G_CURRENCY_SYMBOL} '
                    f'{round(G_TOTAL_COST_EXPIRE, 2)}\n'
                )
            if G_TOTAL_COST_SOON > 0:
                domain_list += (
                    f'For Soon      : '
                    f'{G_CURRENCY_SYMBOL} '
                    f'{round(G_TOTAL_COST_SOON, 2)}\n'
                )
            domain_list += f'{hl}\n'
            domain_list += (
                f'<b>'
                f'Total         : '
                f'{G_CURRENCY_SYMBOL} '
                f'{round(g_total_cost, 2)}'
                f'</b>\n'
            )
            domain_list += '</pre>'

        body_html = body_html.replace('%BODY%', domain_list)

        part_plain = MIMEText(body_text, 'plain')
        part_html = MIMEText(body_html, 'html')

        msg.attach(part_plain)
        msg.attach(part_html)

        message = msg.as_string()

        send_email(email_to, message)


def send_email(email_to: str, message: str) -> None:
    """
    Sending a email to the recipient
    :param email_to: str
    :param message: str
    :return: None
    """
    server = None
    context = None
    # Try to log in to server and send email
    try:
        if CLI.email_ssl or CLI.email_starttls:
            # Create a secure SSL context
            context = ssl.create_default_context()
            context.check_hostname = SMTP_CHECK_SSL_HOSTNAME
            if CLI.email_ssl:
                server = smtplib.SMTP_SSL(
                    host=SMTP_SERVER,
                    port=SMTP_PORT,
                    context=context
                )
            context.verify_mode = ssl.CERT_REQUIRED

        if server is None:
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)

        if CLI.email_starttls:
            server.starttls(context=context)  # Secure the connection

        server.ehlo()  # Can be omitted
        if CLI.email_auth:
            server.login(SMTP_SENDER, SMTP_PASSWORD)
        server.sendmail(SMTP_SENDER, email_to, message)
    except Exception as e:
        # Print any error messages to stdout
        print(f'{FLR}{e}')
    finally:
        server.quit()


class MyParser(argparse.ArgumentParser):
    """
    Redefining the argparse.ArgumentParser class to catch
    parameter setting errors in the command line interface (CLI)
    """
    def error(self, message):
        """
        Overridden error handler
        :param message: str
        :return: None
        """
        sys.stderr.write(f'{FLR}error: {FRC}{message}\n\n')
        self.print_help()
        sys.exit(2)


def process_cli():
    """
    parses the CLI arguments and returns a domain or
        a file with a list of domains etc.
    :return: dict
    """
    process_parser = MyParser(
        formatter_class=argparse.RawTextHelpFormatter,
        conflict_handler='resolve',
        description=f'\t{FC}DNS Domain Expiration Checker{FR}',
        usage=f"""\t{FLB}%(prog)s{FR} [Options]

    \t{FLBC}A simple python script to display or notify a user by email and/or via Telegram
    \tabout the status of the domain and the expiration date.{FR}""",
        epilog=f'{FLBC}© AK545 (Andrey Klimov) 2019..2023, e-mail: ak545 at mail dot ru\n{FR}',
        add_help=False,
    )
    parent_group = process_parser.add_argument_group(
        title='Options'
    )
    parent_group.add_argument(
        '-h',
        '--help',
        action='help',
        help='Help'
    )
    parent_group.add_argument(
        '-v',
        '--version',
        action='version',
        help='Display the version number',
        version=f'{FLC}%(prog)s{FR} version: {FLY}{__version__}{FR}'
    )
    parent_group.add_argument(
        '-f',
        '--file',
        help='Path to the file with the list of domains (default is None)',
        metavar='FILE'
    )
    parent_group.add_argument(
        '-d',
        '--domain',
        help='Domain to check expiration on (default is None)',
        metavar='STRING'
    )
    parent_group.add_argument(
        '-c',
        '--print-to-console',
        action='store_true',
        default=False,
        help='Enable console printing (default is False)'
    )
    parent_group.add_argument(
        '-l',
        '--long-format',
        action='store_true',
        default=False,
        help='Enable detailed print in console (default is False)'
    )
    parent_group.add_argument(
        '-i',
        '--interval-time',
        default=60,
        type=int,
        metavar='SECONDS',
        help='Time to sleep between whois queries (in seconds, default is 60)'
    )
    parent_group.add_argument(
        '-x',
        '--expire-days',
        default=60,
        type=int,
        metavar='DAYS',
        help='Expiration threshold to check against (in days, default is 60)'
    )
    parent_group.add_argument(
        '-s',
        '--cost-per-domain',
        default=0.00,
        type=float,
        metavar='FLOAT',
        help='The cost per one domain (in your currency, default is 0.00)'
    )
    parent_group.add_argument(
        '-twtc',
        '--track-whois-text-changes',
        action='store_true',
        default=False,
        help='Enable whois text change monitoring (default is False)'
    )
    parent_group.add_argument(
        '-split',
        '--split-long-message',
        action='store_true',
        default=False,
        help='Split a long message for Telegram into many short parts (default is False)'
    )
    parent_group.add_argument(
        '-trim',
        '--trim-long-whois-text',
        action='store_true',
        default=False,
        help='Trim long whois text of changes for a domain for Telegram (default is False)'
    )
    parent_group.add_argument(
        '-t',
        '--use-telegram',
        action='store_true',
        default=False,
        help='Send a warning message through the Telegram (default is False)'
    )
    parent_group.add_argument(
        '-p',
        '--proxy',
        help=(
            'Proxy link (for Telegram only), '
            'for example: socks5://127.0.0.1:9150 (default is None)'
        ),
        metavar='URL'
    )
    parent_group.add_argument(
        '-e',
        '--email-to',
        help='Send a warning message to email address (default is None)',
        metavar='EMAIL'
    )
    parent_group.add_argument(
        '-subject',
        '--email-subject',
        help='Append custom text to the email subject (default is None)',
        metavar='STRING'
    )
    parent_group.add_argument(
        '-ssl',
        '--email-ssl',
        action='store_true',
        default=False,
        help='Send email via SSL (default is False)'
    )
    parent_group.add_argument(
        '-auth',
        '--email-auth',
        action='store_true',
        default=False,
        help='Send email via authenticated SMTP (default is False)'
    )
    parent_group.add_argument(
        '-starttls',
        '--email-starttls',
        action='store_true',
        default=False,
        help='Send email via STARTTLS (default is False)'
    )
    parent_group.add_argument(
        '-oe',
        '--use-only-external-whois',
        action='store_true',
        default=False,
        help='Use only external utility whois (default is False)'
    )
    parent_group.add_argument(
        '-ee',
        '--use-extra-external-whois',
        action='store_true',
        default=False,
        help='Use external whois utility for additional analysis (default is False)'
    )
    parent_group.add_argument(
        '-nb',
        '--no-banner',
        action='store_true',
        default=False,
        help='Do not print banner (default is False)'
    )
    return process_parser


def print_namespase() -> None:
    """
    Print preset options to console
    :return: None
    """
    use_internal_whois: bool = True

    if CLI.use_only_external_whois:
        use_internal_whois = False

    print(
        f'\tPreset options\n'
        f'\t-------------------------\n'
        f'\tFile                     : {CLI.file}\n'
        f'\tDomain                   : {CLI.domain}\n'
        f'\tPrint to console         : {CLI.print_to_console}\n'
        f'\tLong Format              : {CLI.long_format}\n'
        f'\tInterval Time            : {CLI.interval_time}\n'
        f'\tExpire Days              : {CLI.expire_days}\n'
        f'\tTrack whois text change  : {CLI.track_whois_text_changes}\n'
        f'\tUse Telegram             : {CLI.use_telegram}\n'
        f'\tTrim long whois text\n'
        f'\tfor Telegram             : {CLI.trim_long_whois_text}\n'
        f'\tSplit long Telegram\n'
        f'\tMessage                  : {CLI.split_long_message}\n'
        f'\tUse Telegram             : {CLI.use_telegram}\n'
        f'\tProxy for Telegram       : {CLI.proxy}\n'
        f'\tEmail to                 : {CLI.email_to}\n'
        f'\tEmail subject            : {CLI.email_subject}\n'
        f'\tEmail SSL                : {CLI.email_ssl}\n'
        f'\tEmail AUTH               : {CLI.email_auth}\n'
        f'\tEmail STARTTLS           : {CLI.email_starttls}\n'
        f'\tUse internal whois       : {use_internal_whois}\n'
        f'\tUse only external whois  : {CLI.use_only_external_whois}\n'
        f'\tUse extra external whois : {CLI.use_extra_external_whois}\n'
        f'\tWhois command timeout    : {WHOIS_COMMAND_TIMEOUT}\n'
        f'\tPrint banner             : {not CLI.no_banner}\n'
        f'\t-------------------------'
    )


def print_hr() -> None:
    """
    Pretty print a formatted horizontal line on stdout
    :return: None
    """
    dn:  str = f'{"-" * 37}'
    wis: str = f'{"-" * 40}'
    reg: str = f'{"-" * 60}'
    exd: str = f'{"-" * 20}'
    dl:  str = f'{"-" * 17}'

    if CLI.long_format:
        print(
            f'{FLW}{dn}{FR} '
            f'{FLW}{wis}{FR} '
            f'{FLW}{reg}{FR} '
            f'{FLW}{exd}{FR} '
            f'{FLW}{dl}{FR}'
        )
    else:
        print(
            f'{FLW}{dn}{FR} '
            f'{FLW}{exd}{FR} '
            f'{FLW}{dl}{FR}'
        )


def print_heading() -> None:
    """
    Pretty print a formatted heading on stdout
    :return: None
    """
    dn: str = 'Domain Name'
    dn = f'{dn:<37}'
    wis: str = 'Whois server'
    wis = f'{wis:<40}'
    reg: str = 'Registrar'
    reg = f'{reg:<60}'
    exd: str = 'Expiration Date'
    exd = f'{exd:<20}'
    dl: str = 'Days Left'
    dl = f'{dl:<17}'

    print_hr()

    if CLI.long_format:
        print(
            f'{FLW}{dn}{FR} '
            f'{FLW}{wis}{FR} '
            f'{FLW}{reg}{FR} '
            f'{FLW}{exd}{FR} '
            f'{FLW}{dl}{FR}'
        )
    else:
        print(
            f'{FLW}{dn}{FR} '
            f'{FLW}{exd}{FR} '
            f'{FLW}{dl}{FR}'
        )
    print_hr()


def print_domain(domain: str,
                 domain_group: str,
                 whois_server: Optional[str],
                 registrar: Optional[str],
                 expiration_date: Optional[datetime],
                 days_remaining: int,
                 expire_days: int,
                 cost: float,
                 current_domain: Optional[int] = None,
                 error: Optional[int] = None) -> None:
    """
    Pretty print the domain information on stdout
    :param domain: str
    :param domain_group: str
    :param whois_server: str
    :param registrar: str
    :param expiration_date: datetime
    :param days_remaining: int
    :param expire_days: int
    :param cost: float
    :param current_domain: int
    :param error: int
    :return: None
    """
    global G_DOMAINS_VALID
    global G_DOMAINS_SOON
    global G_DOMAINS_EXPIRE
    global G_DOMAINS_ERROR
    global G_DOMAINS_FREE
    global G_TOTAL_COST_EXPIRE
    global G_TOTAL_COST_SOON
    global ERRORS_DOMAIN
    global SOON_DOMAIN

    if not domain:
        domain = '-'
    else:
        domain = domain.strip()

    if not whois_server:
        whois_server = '-'
    else:
        whois_server = whois_server.strip()

    if not registrar:
        registrar = '-'
    else:
        registrar = registrar.strip()

    dn: str = f'{domain.lower():<30}'
    wis: str = f'{whois_server:<40}'
    reg: str = f'{registrar:<60}'

    if not expiration_date:
        exd: str = f'{"-" * 20}'
    else:
        if error == 232:
            # TODO: Here you can set your date format
            # exd: str = f'changed {expiration_date:%d.%m.%Y %H:%M}'
            # exd: str = f'changed {expiration_date:%d.%m.%Y}'
            exd: str = f'changed {expiration_date:%Y-%m-%d}'
            exd = f'{exd:<20}'
        else:
            # TODO: Here you can set your date format
            # exd: str = f'{expiration_date:%d.%m.%Y %H:%M}'
            # exd: str = f'{expiration_date:%d.%m.%Y}'
            exd: str = f'{expiration_date:%Y-%m-%d}'
            exd = f'{exd:<20}'

    dl: str = f'{days_remaining:>4}'

    dlerr1: str = "It's free!" if error == 11 else 'Error'
    dlerr1 = f'{dlerr1:<17}'

    dlerr2: str = 'Is it Free?'
    dlerr2 = f'{dlerr2:<17}'

    # Your connection limit exceeded.
    # Please slow down and try again later.
    dlerr3: str = 'Interval is small'
    dlerr3 = f'{dlerr3:<17}'

    dnn: str = ''
    ddl: str = ''
    if days_remaining == -1 or error:
        if error == 2:
            dnn = f'{FLR}{dn}{FR}'
            ddl = f'{FLR}{dlerr3}{FR}'

            tmp_list = []
            if ERRORS_DOMAIN.get(domain_group) is not None:
                tmp_list = ERRORS_DOMAIN[domain_group]
                if domain.lower() not in tmp_list:
                    G_DOMAINS_ERROR += 1
                    tmp_list.append(domain.lower())
                    ERRORS_DOMAIN[domain_group] = tmp_list
            else:
                G_DOMAINS_ERROR += 1
                tmp_list.append(domain.lower())
                ERRORS_DOMAIN[domain_group] = tmp_list

        elif error == 11:
            dnn = f'{FLC}{dn}{FR}'
            ddl = f'{FLC}{dlerr1}{FR}'

            tmp_list = []
            if FREE_DOMAINS.get(domain_group) is not None:
                tmp_list = FREE_DOMAINS[domain_group]
                if domain.lower() not in tmp_list:
                    G_DOMAINS_FREE += 1
                    tmp_list.append(domain.lower())
                    FREE_DOMAINS[domain_group] = tmp_list
            else:
                G_DOMAINS_FREE += 1
                tmp_list.append(domain.lower())
                FREE_DOMAINS[domain_group] = tmp_list

        else:
            dnn = f'{FLR}{dn}{FR}'
            ddl = f'{FLR}{dlerr1}{FR}'

            tmp_list = []
            if ERRORS_DOMAIN.get(domain_group) is not None:
                tmp_list = ERRORS_DOMAIN[domain_group]
                if domain.lower() not in tmp_list:
                    G_DOMAINS_ERROR += 1
                    tmp_list.append(domain.lower())
                    ERRORS_DOMAIN[domain_group] = tmp_list
            else:
                G_DOMAINS_ERROR += 1
                tmp_list.append(domain.lower())
                ERRORS_DOMAIN[domain_group] = tmp_list

    elif days_remaining == -2:
        dnn = f'{FLC}{dn}{FR}'
        ddl = f'{FLC}{dlerr2}{FR}'

        tmp_list = []
        if FREE_DOMAINS.get(domain_group) is not None:
            tmp_list = FREE_DOMAINS[domain_group]
            if domain.lower() not in tmp_list:
                G_DOMAINS_FREE += 1
                tmp_list.append(domain.lower())
                FREE_DOMAINS[domain_group] = tmp_list
        else:
            G_DOMAINS_FREE += 1
            tmp_list.append(domain.lower())
            FREE_DOMAINS[domain_group] = tmp_list

    elif days_remaining < expire_days:
        dnn = f'{FLR}{dn}{FR}'
        ddl = f'{FLR}Expires    {FR}({dl}){FR}'
        G_DOMAINS_EXPIRE += 1
        G_TOTAL_COST_EXPIRE += cost
    else:
        if days_remaining < (expire_days + G_SOON_ADD):
            dnn = f'{FLY}{dn}{FR}'
            ddl = f'{FLY}Soon       {FR}({dl}){FR}'

            tmp_list = []
            tmp_dict = {}
            if SOON_DOMAIN.get(domain_group) is not None:
                tmp_list = SOON_DOMAIN[domain_group]
                tmp_dict[domain.lower()] = days_remaining
                tmp_list.append(tmp_dict)
                SOON_DOMAIN[domain_group] = tmp_list
            else:
                tmp_dict[domain.lower()] = days_remaining
                tmp_list.append(tmp_dict)
                SOON_DOMAIN[domain_group] = tmp_list

            G_DOMAINS_SOON += 1
            G_TOTAL_COST_SOON += cost
        else:
            dnn = f'{FLG}{dn}{FR}'
            ddl = f'{FLG}Valid      {FR}({dl}){FR}'
            G_DOMAINS_VALID += 1

    if not current_domain:
        current_domain = ''

    number_domain: str = f'{current_domain:>5}'
    dnn = f'{number_domain}. {dnn}'
    dnn = f'{dnn:<37}'

    if CLI.long_format:
        print(
            f'{dnn} '
            f'{wis} '
            f'{reg} '
            f'{exd} '
            f'{ddl}'
        )
    elif CLI.print_to_console:
        print(
            f'{dnn} '
            f'{exd} '
            f'{ddl}'
        )
    if error == 22:
        # denic.de
        tmp_list = []
        if ERRORS_DOMAIN.get(domain_group) is not None:
            tmp_list = ERRORS_DOMAIN[domain_group]
            if domain.lower() not in tmp_list:
                G_DOMAINS_ERROR += 1
                tmp_list.append(domain.lower())
                ERRORS_DOMAIN[domain_group] = tmp_list
        else:
            G_DOMAINS_ERROR += 1
            tmp_list.append(domain.lower())
            ERRORS_DOMAIN[domain_group] = tmp_list
        print(
            f"\t{FLBC}The DENIC whois service on port 43 doesn't\n"
            f'\tdisclose any information concerning\n'
            f'\tthe domain holder, general request and abuse contact.\n'
            f'\tThis information can be obtained through use of our\n'
            f'\tweb-based whois service available at the DENIC website:\n'
            f'\thttp://www.denic.de/en/domains/whois-service/web-whois.html{FR}\n'
        )
    elif error == 23:
        # *.nz
        # https://www.dnc.org.nz/whois/search?domain_name=stuff.co.nz
        tmp_list = []
        if ERRORS_DOMAIN.get(domain_group) is not None:
            tmp_list = ERRORS_DOMAIN[domain_group]
            if domain.lower() not in tmp_list:
                G_DOMAINS_ERROR += 1
                tmp_list.append(domain.lower())
                ERRORS_DOMAIN[domain_group] = tmp_list
        else:
            G_DOMAINS_ERROR += 1
            tmp_list.append(domain.lower())
            ERRORS_DOMAIN[domain_group] = tmp_list
        print(
            f'\t{FLBC}Additional information may be available at '
            f'https://www.dnc.org.nz/whois/search?domain_name={FY}{domain}{FR}\n'
        )
    elif error == 231:
        # *.nz new version of this site
        tmp_list = []
        if ERRORS_DOMAIN.get(domain_group) is not None:
            tmp_list = ERRORS_DOMAIN[domain_group]
            if domain.lower() not in tmp_list:
                G_DOMAINS_ERROR += 1
                tmp_list.append(domain.lower())
                ERRORS_DOMAIN[domain_group] = tmp_list
        else:
            G_DOMAINS_ERROR += 1
            tmp_list.append(domain.lower())
            ERRORS_DOMAIN[domain_group] = tmp_list
        print(
            f'\t{FLBC}Additional information may be available at '
            f'https://dnc.org.nz/whois/whois-lookup/?domain_name={FY}{domain}{FR}\n'
        )
    elif error == 232:
        # *.es Fucking bureaucrats
        tmp_list = []
        if ERRORS_DOMAIN.get(domain_group) is not None:
            tmp_list = ERRORS_DOMAIN[domain_group]
            if domain.lower() not in tmp_list:
                G_DOMAINS_ERROR += 1
                tmp_list.append(domain.lower())
                ERRORS_DOMAIN[domain_group] = tmp_list
        else:
            G_DOMAINS_ERROR += 1
            tmp_list.append(domain.lower())
            ERRORS_DOMAIN[domain_group] = tmp_list
        print(
            f'\t{FLBC}Additional information may be available at '
            f'https://www.dominios.es/\n'
        )
    elif error == 24:
        # whois.afilias.net
        tmp_list = []
        if ERRORS_DOMAIN.get(domain_group) is not None:
            tmp_list = ERRORS_DOMAIN[domain_group]
            if domain.lower() not in tmp_list:
                G_DOMAINS_ERROR += 1
                tmp_list.append(domain.lower())
                ERRORS_DOMAIN[domain_group] = tmp_list
        else:
            G_DOMAINS_ERROR += 1
            tmp_list.append(domain.lower())
            ERRORS_DOMAIN[domain_group] = tmp_list
        print(
            f'\t{FLBC}The registration of this domain is restricted,\n'
            f'\tas it is protected by the identity digital dpml\n'
            f'\tbrand protection policy.\n'
            f'\tAdditional information can be found at\n'
            f'\thttps://www.identity.digital/what-we-do/brand-protection\n'
            f'\t(But most likely this page does not exist){FR}\n'
        )
    elif error == 25:
        # whois Connection timed out
        print(
            f'\t{FLBC}Connection timed out{FR}\n'
        )
    elif error == 26:
        # Failed to retrieve the WHOIS record of the specified domain
        print(
            f'\t{FLBC}Failed to retrieve the WHOIS record of the specified domain{FR}\n'
        )


def print_stat() -> None:
    """
    Print stat to console
    :return: None
    """
    print(
        f'The Result\n'
        f'---------------\n'
        f'Total         : {FLW}{G_DOMAINS_TOTAL}{FR}\n'
        f'Valid         : {FLG}{G_DOMAINS_VALID}{FR}\n'
        f'Soon          : {FLY}{G_DOMAINS_SOON}{FR}\n'
        f'Expires       : {FLR}{G_DOMAINS_EXPIRE}{FR}\n'
        f'Errors        : {FLR}{G_DOMAINS_ERROR}{FR}\n'
        f'Free          : {FLC}{G_DOMAINS_FREE}{FR}'
    )
    g_total_cost = G_TOTAL_COST_SOON + G_TOTAL_COST_EXPIRE
    if g_total_cost > 0:
        print('---------------')
        print('Cost:')
        print('---------------')
        if G_TOTAL_COST_SOON > 0:
            print(
                f'For Soon      : '
                f'{FLY}{G_CURRENCY_SYMBOL} '
                f'{round(G_TOTAL_COST_SOON, 2)}'
            )
        if G_TOTAL_COST_EXPIRE > 0:
            print(
                f'For Expires   : '
                f'{FLR}{G_CURRENCY_SYMBOL} '
                f'{round(G_TOTAL_COST_EXPIRE, 2)}'
            )
        print('---------------')
        print(
            f'Total         : '
            f'{FLW}{G_CURRENCY_SYMBOL} '
            f'{round(g_total_cost, 2)}'
        )
        print('---------------\n')


def check_domain(domain_name: str,
                 domain_group: str,
                 expiration_days: int,
                 cost: float,
                 interval_time: Optional[int] = None,
                 current_domain: int = 0,
                 checking_whois_text_changes: bool = True) -> bool:
    """
    Check domain
    :param domain_name: str
    :param domain_group: str
    :param expiration_days: int
    :param cost: float
    :param interval_time: int or None
    :param current_domain: int
    :param checking_whois_text_changes: bool
    :return: bool (False - Error, True - Successfully)
    """
    global EXPIRES_DOMAIN
    global SOON_DOMAIN
    global ERRORS_DOMAIN
    global ERRORS2_DOMAIN
    global FREE_DOMAINS
    global WHOIS_TEXT_CHANGED_DOMAIN

    if domain_group == '':
        domain_group = '/'

    is_internal_error: bool = False
    if not interval_time:
        interval_time = CLI.interval_time

    expiration_date: Optional[any] = None
    registrar: Optional[str] = None
    whois_server: Optional[str] = None
    ret_error: Optional[int] = None

    whois_data: Optional[str] = None

    if CLI.use_only_external_whois:
        (
            whois_data,
            expiration_date,
            registrar,
            whois_server,
            ret_error
        ) = make_whois_query(
            domain=domain_name,
            domain_group=domain_group
        )
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        # Init colorama again
        init(autoreset=True)
    else:
        w: Optional[Any] = None
        sys.stdout = os.devnull
        sys.stderr = os.devnull
        try:
            flags: int = 0
            flags = flags | whois.NICClient.WHOIS_QUICK
            # flags = flags | whois.NICClient.WHOIS_RECURSE
            w = whois.whois(
                url=domain_name,
                flags=flags
            )
            if w is not None:
                whois_data = w.text
        except Exception:
            is_internal_error = True
            ret_error = 1
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        # Init colorama again
        init(autoreset=True)

        if not is_internal_error:
            is_internal_error = w is None

        if not is_internal_error:
            expiration_date = w.get('expiration_date')
            registrar = w.get('registrar')
            whois_server = w.get('whois_server')
            is_internal_error = expiration_date is None

        if is_internal_error:
            if CLI.use_extra_external_whois:
                (
                    whois_data,
                    expiration_date_e,
                    registrar_e,
                    whois_server_e,
                    ret_error
                ) = make_whois_query(
                    domain=domain_name,
                    domain_group=domain_group
                )

                if ret_error is not None:
                    if ret_error in (1, 22):
                        tmp_list = []
                        if ERRORS_DOMAIN.get(domain_group) is not None:
                            tmp_list = ERRORS_DOMAIN[domain_group]
                            if domain_name.lower() not in tmp_list:
                                tmp_list.append(domain_name.lower())
                                ERRORS_DOMAIN[domain_group] = tmp_list
                        else:
                            tmp_list.append(domain_name.lower())
                            ERRORS_DOMAIN[domain_group] = tmp_list

                    elif ret_error == 2:
                        # Exceeded the limit on whois
                        tmp_list = []
                        if ERRORS2_DOMAIN.get(domain_group) is not None:
                            tmp_list = ERRORS2_DOMAIN[domain_group]
                            if domain_name.lower() not in tmp_list:
                                tmp_list.append(domain_name.lower())
                                ERRORS2_DOMAIN[domain_group] = tmp_list
                        else:
                            tmp_list.append(domain_name.lower())
                            ERRORS2_DOMAIN[domain_group] = tmp_list

                if not expiration_date:
                    expiration_date = expiration_date_e
                if not registrar:
                    registrar = registrar_e
                if not whois_server:
                    whois_server = whois_server_e
            else:
                tmp_list = []
                if ERRORS_DOMAIN.get(domain_group) is not None:
                    tmp_list = ERRORS_DOMAIN[domain_group]
                    if domain_name.lower() not in tmp_list:
                        tmp_list.append(domain_name.lower())
                        ERRORS_DOMAIN[domain_group] = tmp_list
                else:
                    tmp_list.append(domain_name.lower())
                    ERRORS_DOMAIN[domain_group] = tmp_list

                print_domain(
                    domain=domain_name,
                    domain_group=domain_group,
                    whois_server=None,
                    registrar=None,
                    expiration_date=None,
                    days_remaining=-1,
                    expire_days=-1,
                    cost=cost,
                    current_domain=current_domain,
                    error=ret_error
                )  # Error
                if current_domain < G_DOMAINS_TOTAL and interval_time is not None:
                    if CLI.print_to_console:
                        print(f'\tWait {interval_time} sec...\r', end='')
                    time.sleep(interval_time)
                return False

    if not whois_server and not registrar and not expiration_date:
        print_domain(
            domain=domain_name,
            domain_group=domain_group,
            whois_server=whois_server,
            registrar=registrar,
            expiration_date=expiration_date,
            days_remaining=-2,
            expire_days=-1,
            cost=cost,
            current_domain=current_domain,
            error=ret_error
        )  # Free ?
        if current_domain < G_DOMAINS_TOTAL and interval_time is not None:
            if CLI.print_to_console:
                print(f'\tWait {interval_time} sec...\r', end='')
            time.sleep(interval_time)
        return False

    if not expiration_date:
        print_domain(
            domain=domain_name,
            domain_group=domain_group,
            whois_server=whois_server,
            registrar=registrar,
            expiration_date=expiration_date,
            days_remaining=-1,
            expire_days=-1,
            cost=cost,
            current_domain=current_domain,
            error=ret_error
        )  # Error
        if current_domain < G_DOMAINS_TOTAL and interval_time is not None:
                if CLI.print_to_console:
                    print(f'\tWait {interval_time} sec...\r', end='')
                time.sleep(interval_time)
        return False

    if 'datetime.datetime' in str(type(expiration_date)):
        expiration_date_min = expiration_date
    else:
        expiration_date_min = max(expiration_date)

    days_remaining: int = calculate_expiration_days(expiration_date_min)

    print_domain(
        domain=domain_name,
        domain_group=domain_group,
        whois_server=whois_server,
        registrar=registrar,
        expiration_date=expiration_date_min,
        days_remaining=days_remaining,
        expire_days=expiration_days,
        cost=cost,
        current_domain=current_domain,
        error=ret_error
    )

    if days_remaining < expiration_days:

        tmp_list = []
        tmp_dict = {}
        if EXPIRES_DOMAIN.get(domain_group) is not None:
            tmp_list = EXPIRES_DOMAIN[domain_group]
            tmp_dict[domain_name.lower()] = days_remaining
            tmp_list.append(tmp_dict)
            EXPIRES_DOMAIN[domain_group] = tmp_list
        else:
            tmp_dict[domain_name.lower()] = days_remaining
            tmp_list.append(tmp_dict)
            EXPIRES_DOMAIN[domain_group] = tmp_list

    # Start of Monitoring whois-text changes
    if checking_whois_text_changes:
        if (whois_data is not None) and (str(whois_data).strip() != ''):
            whois_data: str = str(whois_data).strip()
            file: str = f'{domain_name.lower()}.json'
            last_cache: Optional[Dict] = load_whois_cache(file)
            curr_cache: Dict = {
                'txt': whois_data,
                'dt': f'{datetime.now():%Y.%m.%d %H:%M:%S}'
            }
            if CLI.track_whois_text_changes:
                if last_cache:
                    if last_cache.get('txt') != '':
                        delta = compare_whois_text(
                            f1=last_cache.get('txt'),
                            f2=whois_data,
                            domain=domain_name.lower()
                        )
                        if delta != '':
                            delta_lines = delta.splitlines()
                            d_txt = ''
                            print('\r', end='')
                            for line in delta_lines:
                                d_txt += f'{line}\n'
                                print(f'{" " * 7}{line}')
                            print('')
                            tmp_list = []
                            tmp_dict = {}
                            if WHOIS_TEXT_CHANGED_DOMAIN.get(domain_group) is not None:
                                tmp_list = WHOIS_TEXT_CHANGED_DOMAIN[domain_group]
                                tmp_dict[domain_name.lower()] = {
                                    'txt': remove_control_characters_of_colorama(d_txt),
                                    'dt': f'{datetime.now():%Y.%m.%d %H:%M:%S}'
                                }
                                tmp_list.append(tmp_dict)
                                WHOIS_TEXT_CHANGED_DOMAIN[domain_group] = tmp_list
                            else:
                                tmp_dict[domain_name.lower()] = {
                                    'txt': remove_control_characters_of_colorama(d_txt),
                                    'dt': f'{datetime.now():%Y.%m.%d %H:%M:%S}'
                                }
                                tmp_list.append(tmp_dict)
                                WHOIS_TEXT_CHANGED_DOMAIN[domain_group] = tmp_list

            save_whois_cache(file, curr_cache)
    # End of Monitoring whois-text changes

    return True


def is_domain_supported(domain: str, domain_group: str) -> bool:
    """
    Domain support check
    :param domain: str
    :param domain_group: str
    :return: bool
    """
    global ERRORS_DOMAIN
    global G_DOMAINS_ERROR

    if domain.lower().endswith(UNSUPPORTED_DOMAINS):

        tmp_list = []
        if ERRORS_DOMAIN.get(domain_group) is not None:
            tmp_list = ERRORS_DOMAIN[domain_group]
            if domain.lower() not in tmp_list:
                G_DOMAINS_ERROR += 1
                tmp_list.append(domain.lower())
                ERRORS_DOMAIN[domain_group] = tmp_list
        else:
            G_DOMAINS_ERROR += 1
            tmp_list.append(domain.lower())
            ERRORS_DOMAIN[domain_group] = tmp_list

        return False
    return True


def prepare_domains_list(file: str) -> None:
    """
    Prepare Domains List from file
    :param file: str
    :return: None
    """
    global G_DOMAINS_LIST
    global G_DOMAINS_TOTAL

    G_DOMAINS_LIST = []
    G_DOMAINS_TOTAL = 0
    domain_dict: Dict = {}

    with open(file, 'r', encoding='utf-8', newline='\n') as domains_to_process:
        i: int = 0
        current_group: str = '/'
        for line in domains_to_process:
            domain_dict.clear()

            domain_dict.update({
                'group': '',
                'domain': '',
                'expire_days': -1,
                'interval_time': CLI.interval_time,
                'cost': CLI.cost_per_domain,
                'supported': True,
                'checking_whois_text_changes': CLI.track_whois_text_changes,
            })

            try:
                ss: str = line.strip()
                if len(ss) == 0:
                    continue
                else:
                    if ss.lstrip().startswith('!'):
                        # the group header
                        i += 1
                        header: str = ss.partition('!')[2].strip()
                        current_group = header

                        domain_dict['group'] = header
                        domain_dict['domain'] = ''
                        domain_dict['expire_days'] = -1
                        domain_dict['interval_time'] = -1
                        domain_dict['cost'] = 0.00
                        domain_dict['supported'] = True
                        domain_dict['checking_whois_text_changes'] = CLI.track_whois_text_changes
                        G_DOMAINS_LIST.append(domain_dict.copy())
                        continue

                    if ss.lstrip().startswith('#'):
                        # the comment
                        continue

                    # the domain?
                    word_list: List = ss.lower().split()
                    if len(word_list) > 0:
                        domain_name: str = word_list[0].strip()
                        if (":" in domain_name) or (domain_name.isdigit()):
                            # Broken line, this is not domain
                            continue

                        domain_dict['domain'] = domain_name
                        domain_dict['supported'] = is_domain_supported(domain_name, domain_group=current_group)
                        G_DOMAINS_TOTAL += 1

                        if len(word_list) > 1:
                            # If the string contains the interval value in
                            # seconds and/or the expiration value in days
                            for i, item in enumerate(word_list):
                                if i == 0:
                                    # domain name - skip
                                    continue

                                if 'sleep:' in item:
                                    # the interval value in seconds
                                    interval_time: int = int(
                                        item.partition('sleep:')[2].strip())
                                    domain_dict['interval_time'] = interval_time
                                elif 'cost:' in item:
                                    # the cost of this domain
                                    cost: float = float(
                                        item.partition('cost:')[2].strip())
                                    domain_dict['cost'] = cost
                                elif 'skip_checking_whois_text_changes' in item:
                                    # skip checking whois text changes for this domain
                                    domain_dict['checking_whois_text_changes'] = False
                                else:
                                    # the expiration value in days
                                    domain_dict['expire_days'] = int(item)
                        else:
                            domain_dict['expire_days'] = CLI.expire_days

                        G_DOMAINS_LIST.append(domain_dict.copy())

            except Exception as e:
                err: str = (
                    f'Unable to parse the file with the list of domains.\n'
                    f'Problem line\n'
                    f'\'{line.strip()}\'\n'
                    f'Error: {str(e)}'
                )
                print(f'{FLR}{err}')
                sys.exit(1)


def check_cli_logic() -> None:
    """
    Check command line logic
    :return: None
    """
    global CLI
    global TELEGRAM_PROXIES

    if CLI.print_to_console and not CLI.no_banner:
        # Print banner
        if platform.platform().startswith('Windows'):
            home_path: str = os.path.join(
                os.getenv('HOMEDRIVE'), os.getenv('HOMEPATH')
            )
        else:
            home_path: str = os.path.join(os.getenv('HOME'))
        sys_version: str = str(sys.version).replace('\n', '')
        print(
            f'\tPython  : {FLC}{sys_version}{FR}\n'
            f'\tNode    : {FLC}{platform.node()}{FR}\n'
            f'\tHome    : {FLC}{home_path}{FR}\n'
            f'\tOS      : {FLC}{platform.system()}{FR}\n'
            f'\tRelease : {FLC}{platform.release()}{FR}\n'
            f'\tVersion : {FLC}{platform.version()}{FR}\n'
            f'\tArch    : {FLC}{platform.machine()}{FR}\n'
            f'\tCPU     : {FLC}{platform.processor()}{FR}'
        )
        print_namespase()

    if CLI.use_only_external_whois or CLI.use_extra_external_whois:
        if not Path(WHOIS_COMMAND).is_file():
            whois_check()
        elif not CLI.no_banner:
            print(
                f'\tThe {FLG}whois{FR} found in: {FC}{WHOIS_COMMAND}'
            )

    if CLI.trim_long_whois_text and (not CLI.use_telegram):
        print(
            f'{FLR}The -trim/--trim-long-whois-text option is used '
            f'in conjunction with the -t/--use-telegram option'
        )
        sys.exit(-1)

    if CLI.split_long_message and (not CLI.use_telegram):
        print(
            f'{FLR}The -split/--split-long-message option is used '
            f'in conjunction with the -t/--use-telegram option'
        )
        sys.exit(-1)

    if CLI.use_only_external_whois and CLI.use_extra_external_whois:
        print(
            f'{FLR}One of the parameters is superfluous. '
            f'Use either --use-only-external-whois or --use-extra-external-whois'
        )
        sys.exit(-1)

    if CLI.long_format and (not CLI.print_to_console):
        CLI.print_to_console = True

    if (not CLI.print_to_console and (CLI.file or CLI.domain)) and (
            (not CLI.use_telegram) and (not CLI.email_to)):
        print(
            f'{FLR}You must use at least one of the notification methods '
            f'(email, telegram or console)\n'
            f'Use --print-to-console or --email-to or/and --use-telegram'
        )
        sys.exit(-1)

    if CLI.email_ssl and (not CLI.email_to):
        print(
            f'{FLR}You must specify the email address of the recipient. '
            f'Use the --email-to option'
        )
        sys.exit(-1)

    if CLI.email_subject and (not CLI.email_to):
        print(
            f'{FLR}You must specify the email address of the recipient. '
            f'Use the --email-to option'
        )
        sys.exit(-1)

    if CLI.email_auth and (not CLI.email_to):
        print(
            f'{FLR}You must specify the email address of the recipient. '
            f'Use the --email-to option'
        )
        sys.exit(-1)

    if CLI.email_starttls and (not CLI.email_to):
        print(
            f'{FLR}You must specify the email address of the recipient. '
            f'Use the --email-to option'
        )
        sys.exit(-1)

    if CLI.email_starttls and CLI.email_ssl and CLI.email_to:
        print(
            f'{FLR}The contradiction of options. You must choose one thing: '
            f'either --email-ssl or '
            f'--email-starttls or do not use either one or the other'
        )
        sys.exit(-1)

    if CLI.file and CLI.domain:
        print(
            f'{FLR}One of the parameters is superfluous. '
            f'Use either --file or --domain'
        )
        sys.exit(-1)

    if CLI.proxy and (not CLI.use_telegram):
        print(f'{FLR}The proxy setting is for telegram only')
        sys.exit(-1)

    if CLI.proxy and CLI.use_telegram:
        TELEGRAM_PROXIES.clear()
        TELEGRAM_PROXIES['http'] = CLI.proxy
        TELEGRAM_PROXIES['https'] = CLI.proxy

    if CLI.print_to_console:
        print_heading()


def main() -> None:
    """
    Main function
    :return: None
    """
    global EXPIRES_DOMAIN
    global SOON_DOMAIN
    global ERRORS_DOMAIN
    global ERRORS2_DOMAIN
    global FREE_DOMAINS
    global WHOIS_TEXT_CHANGED_DOMAIN

    # Check command line logic
    check_cli_logic()

    EXPIRES_DOMAIN = {}
    SOON_DOMAIN = {}
    ERRORS_DOMAIN = {}
    ERRORS2_DOMAIN = {}
    FREE_DOMAINS = {}
    WHOIS_TEXT_CHANGED_DOMAIN = {}

    if CLI.track_whois_text_changes:
        try:
            Path(WHOIS_CACHE_PATH).mkdir(
                parents=True, exist_ok=True
            )
        except:
            print(
                f'Error creating folder: '
                f'{FLR}{WHOIS_CACHE_PATH}'
            )
            sys.exit(-1)

    if CLI.file:
        # Source data from file
        file: str = CLI.file.strip()
        if not Path(file).is_file():
            print(f'{FLR}File {FLY}{file}{FLR} not found')
            sys.exit(-1)

        # Prepare domains list
        prepare_domains_list(CLI.file)

        current_group: str = '/'

        if G_DOMAINS_TOTAL > 0:
            i: int = 0
            current_domain: int = 0

            for item in G_DOMAINS_LIST:
                expiration_days: int = CLI.expire_days
                group: str = item['group']

                domain: str = item['domain']
                expire_days: int = item['expire_days']
                interval_time: int = item['interval_time']
                cost: float = item['cost']
                is_supported: bool = item['supported']
                is_checking_whois_text_changes: bool = item['checking_whois_text_changes']

                if group != "":
                    current_group = group
                    i += 1
                    si: str = f'{i:>4}'
                    if i == 1:
                        if CLI.print_to_console:
                            print(f'{si}. {FLW}{group}')
                    else:
                        if CLI.print_to_console:
                            print(' ' * 40, end='')
                            print(f'\n{si}. {FLW}{group}')
                    continue

                if expire_days > 0:
                    expiration_days = expire_days

                if interval_time == -1:
                    interval_time = None

                if domain != '':
                    current_domain += 1
                    domain_name: str = domain

                    if not is_supported:
                        dn: str = f'{domain_name.lower():<35}'
                        dnn: str = f'{FLR}{dn}'
                        number_domain: str = f"{current_domain:>5}"
                        dnn: str = f'{number_domain}. {dnn}'
                        dnn: str = f'{dnn:<37}'
                        print(f'{dnn} Sorry, this domain is not supported.')
                    else:
                        # Domain Check
                        if not check_domain(
                                domain_name=domain_name,
                                domain_group=current_group,
                                expiration_days=expiration_days,
                                cost=cost,
                                interval_time=interval_time,
                                current_domain=current_domain,
                                checking_whois_text_changes=is_checking_whois_text_changes
                        ):
                            # If error - skip
                            continue

                    # Need to wait between queries to avoid triggering DOS measures like so:
                    # Your IP has been restricted due to excessive access, please wait a bit
                    if current_domain < G_DOMAINS_TOTAL and interval_time is not None:
                        if CLI.print_to_console:
                            print(
                                f'\tWait {interval_time} sec...\r',
                                end=''
                            )
                        time.sleep(interval_time)

            if CLI.print_to_console:
                print(f'{" " * 38}\r', end='')
                print_hr()
                print_stat()
                print('Process complete.')
                # if (
                #         G_DOMAINS_SOON > 0 or
                #         G_DOMAINS_EXPIRE > 0 or
                #         G_DOMAINS_ERROR > 0 or
                #         G_DOMAINS_FREE > 0
                # ):
                #     time.sleep(10)

    elif CLI.domain:
        # Source data - one domain from the command line
        domain_name: str = CLI.domain
        expiration_days: int = CLI.expire_days
        cost: float = CLI.cost_per_domain
        is_supported: bool = is_domain_supported(domain_name, domain_group='/')

        if not is_supported:
            dn: str = f'{domain_name.lower():<35}'
            dnn: str = f'{FLR}{dn}'
            number_domain: str = f'{"1":>5}'
            dnn: str = f'{number_domain}. {dnn}'
            dnn: str = f'{dnn:<37}'
            print(f'{dnn} Sorry, this domain is not supported.')
        else:
            # Domain Check
            check_domain(
                domain_name=domain_name,
                domain_group='',
                expiration_days=expiration_days,
                cost=cost,
                interval_time=None,
                current_domain=1,
                checking_whois_text_changes=CLI.track_whois_text_changes
            )

        if CLI.print_to_console:
            print_hr()
            print('Process complete.')

    if (
            len(EXPIRES_DOMAIN) > 0 or
            len(SOON_DOMAIN) > 0 or
            len(ERRORS_DOMAIN) > 0 or
            len(ERRORS2_DOMAIN) > 0 or
            len(FREE_DOMAINS) > 0 or
            len(WHOIS_TEXT_CHANGED_DOMAIN) > 0
    ):
        if CLI.email_to:
            make_report_for_email()

        if CLI.use_telegram:
            make_report_for_telegram()


if __name__ == '__main__':
    # Parsing command line
    parser: MyParser = process_cli()
    CLI = parser.parse_args(sys.argv[1:])
    if len(sys.argv[1:]) == 0:
        parser.print_help()
    main()
