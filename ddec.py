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
# Carl Mercier
# https://github.com/cmer
#
# Current Version: 0.2.8
# Creation Date: 2019-07-05
# Last Fix Date: 2020-12-01
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
import os
import sys
import platform
import argparse
import time
from datetime import datetime
import dateutil.parser
import requests
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
import subprocess

try:
    import whois
except ImportError:
    sys.exit(
        """You need python-whois!
                install it from http://pypi.python.org/pypi/python-whois
                or run pip install python-whois"""
    )
try:
    from colorama import init
    from colorama import Fore, Back, Style
except ImportError:
    sys.exit(
        """You need colorama!
                install it from http://pypi.python.org/pypi/colorama
                or run pip install colorama"""
    )

# Init colorama
init(autoreset=True)

# Check Python Version
if sys.version_info < (3, 6):
    print("Error. Python version 3.6 or later required to run this script")
    print("Your version:", sys.version)
    sys.exit(-1)


# Global constants
__version__ = "0.2.8"
FR = Fore.RESET
FLW = Fore.LIGHTWHITE_EX
FLG = Fore.LIGHTGREEN_EX
FLR = Fore.LIGHTRED_EX
FLC = Fore.LIGHTCYAN_EX
FLY = Fore.LIGHTYELLOW_EX
BLB = Back.LIGHTBLACK_EX
BR = Back.RESET
SDIM = Style.DIM
SNORMAL = Style.NORMAL
SBRIGHT = Style.BRIGHT
SR = Style.RESET_ALL

SEP = os.sep

# SMTP options
SMTP_SERVER = os.getenv("SMTP_SERVER", "localhost")
SMTP_PORT = int(os.getenv("SMTP_PORT", 25))

# SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
# SMTP_PORT = int(os.getenv("SMTP_PORT", 587))  # For starttls

# SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.mail.ru")
# SMTP_PORT = int(os.getenv("SMTP_PORT", 25))  # Default

# SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.yandex.ru")
# SMTP_PORT = int(os.getenv("SMTP_PORT", 465))  # For SSL

SMTP_SENDER = os.getenv("SMTP_SENDER", "root")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "P@ssw0rd")

if str(os.getenv("SMTP_CHECK_SSL_HOSTNAME")) == "0":
    SMTP_CHECK_SSL_HOSTNAME = False
else:
    SMTP_CHECK_SSL_HOSTNAME = True

REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/69.0.3497.57 Safari/537.36"
}

# Telegram bot options
# Proxy for telegram
TELEGRAM_PROXIES = {}
# TELEGRAM_PROXIES = {
#     'http': 'socks5://127.0.0.1:9150',
#     'https': 'socks5://127.0.0.1:9150',
# }

# Get help from https://core.telegram.org/bots
# token that can be generated talking with @BotFather on telegram
TELEGRAM_TOKEN = '<INSERT YOUR TOKEN>'

# channel id for telegram
TELEGRAM_CHAT_ID = '<INSERT YOUR CHANNEL ID>'

# url for post request to api.telegram.org
TELEGRAM_URL = "https://api.telegram.org/bot" + TELEGRAM_TOKEN + "/"

# Options for an external utility whois
# Keywords for whois-data
EXPIRE_STRINGS = [
    "Registry Expiry Date:",
    "Expiration:",
    "Domain Expiration Date:",
    "Registrar Registration Expiration Date:",
    "expire:",
    "paid-till:",
    "option expiration date:",
    "[Expires on]",
    "Expiry date:",
    "Expiry Date:",
    "Expiration date:",
    "Expiration Date:",
    "Expiration Time:",
    "Renewal date:",
    "paid-till:",
    "Domain expires:",
    "renewal date:",
    "expires:",
    "Expires:",
    "Expires On:"
]
REGISTRAR_STRINGS = [
    "[Registrant]",
    "Registrar:",
    "registrar:",
    "Registrant:",
    # "Status:",
    "Sponsoring Registrar:",
    "REGISTRAR:"
]
WHOIS_SERVER_STRINGS = [
    "Registrar WHOIS Server:",
    "WHOIS Server:"
]
NOT_FOUND_STRINGS = [
    "NOT FOUND",
    "No entries found for the selected source(s)."
]

# Command for external whois
WHOIS_COMMAND = "whois"

# Timeout for external whois
WHOIS_COMMAND_TIMEOUT = 10

# The list of expired domains
EXPIRES_DOMAIN = {}

# The list of error domains
ERRORS_DOMAIN = []  # Common errors
ERRORS2_DOMAIN = []  # limit connection

# Command line parameters
CLI = None

# The number of days that are added to the expiration
# date of the domain registration
# in order to mark the expiration of the domain that
# is coming soon
G_SOON_ADD = 21

# List of domains processed from file
G_DOMAINS_LIST = []


# Currency symbol
G_CURRENCY_SYMBOL = '$'
# G_CURRENCY_SYMBOL = '₽'

# Counters:
# Total Domains
G_DOMAINS_TOTAL = 0

# Valid Domains
G_DOMAINS_VALID = 0

# Soon Domains
G_DOMAINS_SOON = 0

# The total price for the domains of this group
G_TOTAL_COST_SOON = 0

# Expired Domains
G_DOMAINS_EXPIRE = 0

# The total price for the domains of this group
G_TOTAL_COST_EXPIRE = 0

# Error Domains
G_DOMAINS_ERROR = 0


def whois_check():
    """
    External whois availability check
    :return: None
    """
    str_tmp = ""
    whois_found = False
    if sys.platform == "win32":
        delemiter = ";"
        s_path = "Path"
    else:
        delemiter = ":"
        s_path = "PATH"
    os_env_path = os.environ.get(s_path).split(delemiter)
    for item in os_env_path:
        str_tmp = item
        if str_tmp != '':
            if str_tmp[-1] != SEP:
                str_tmp += SEP + "whois"
                if sys.platform == "win32":
                    str_tmp += ".exe"
            if Path(str_tmp).is_file():
                whois_found = True
                break

    if whois_found:
        if not CLI.no_banner:
            print(
                f"\tThe {FLG}whois{FR} found in: {FLW}{str_tmp}"
            )
    else:
        print(f"\tThe {FLR}whois{FR} not found!")
        if sys.platform == "win32":
            print(
                "\tPlease, install the cygwin from "
                "https://www.cygwin.com/ to c:\\cygwin64 (as sample)\n"
                "\tChoice in installer whois and install it.\n"
                "\tAfter it, add path to c:\\cygwin64\\bin to system PATH variable.\n"
            )
        elif sys.platform == "linux":
            print(
                "\tPlease, install the whois\n\n"
                "\t\tFor Ubuntu/Debian:\n"
                "\t\t\tsudo apt update && sudo apt upgrade\n"
                "\t\t\tsudo apt install whois\n\n"

                "\t\tFor RHEL/CentOS/Fedora:\n"
                "\t\t\tFor RHEL 6.x/CentOS 6.x:\n"
                "\t\t\t\tsudo yum install jwhois\n\n"

                "\t\t\tFor RHEL 7.x/CentOS 7.x/Fedora 22 and later:\n"
                "\t\t\t\tsudo dnf install jwhois\n\n"

                "\t\tFor Arch/Manjaro:\n"
                "\t\t\tsudo pacman -S whois\n"
            )
        elif sys.platform == "darwin":
            print(
                "\tPlease, install the whois\n"
                "\t\tbrew install whois\n"
            )
    if not whois_found:
        sys.exit(-1)


def make_whois_query(domain):
    """
    Execute a external whois and parse the data to extract specific data
    :param domain: string
    :return: date, string, string, boolean (expiration_date, registrar, whois_server, error)
    """
    global ERRORS_DOMAIN

    try:
        p = subprocess.Popen([WHOIS_COMMAND, domain],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except Exception as e:
        print(
            f"{FLR}Unable to Popen() the whois binary.\nDomain: {domain}.\nException: {e}")
        sys.exit(-1)

    try:
        whois_data = p.communicate(timeout=WHOIS_COMMAND_TIMEOUT)[0]
    except Exception as e:
        if domain not in ERRORS_DOMAIN:
            ERRORS_DOMAIN.append(str(domain).lower())
        return None, None, None, 1

    # TODO: Work around whois issue #55 which returns a non-zero
    # exit code for valid domains.
    # if p.returncode != 0:
    #    print("The WHOIS utility exit()'ed with a non-zero return code")
    #    sys.exit(-1)

    whois_data = str(whois_data, 'utf-8', 'ignore')

    return parse_whois_data(domain, whois_data)


def parse_whois_data(domain, whois_data):
    """
    Grab the registrar and expiration date from the WHOIS data
    :param domain: string
    :param whois_data: string
    :return: date, string, string, boolean (expiration_date, registrar, whois_server, error)
    """
    global ERRORS2_DOMAIN

    expiration_date = None
    registrar = None
    whois_server = None
    error = None

    if 'No entries found for the selected source(s)' in str(whois_data):
        # It is Free!
        error = 11
        return None, None, None, error

    if 'http://www.denic.de/en/domains/whois-service/web-whois.html' in str(whois_data):
        # denic.de
        error = 22
        return None, None, None, error

    if 'https://whois.dot.ph/' in str(whois_data):
        # whois.dot.ph
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:45.0) Gecko/20100101 Firefox/45.0'
        }
        try:
            page = requests.get(
                f'https://whois.dot.ph/?utf8=%E2%9C%93&search={domain}',
                headers=headers
            )
        except requests.exceptions.RequestException:
            print(f'{FLR}Failed to fetch remote blocklist providers. Continue...')
            return

        html = page.content.decode('utf-8', 'ignore')
        if 'var expiryDate = moment(' in html:
            for line in html.splitlines():
                if 'var expiryDate = moment(' in line:
                    if 'Registrar:' in line:
                        registrar = line.replace(
                            "Registrar:", ""
                        ).replace(
                            "<br>", ""
                        )

                    str_date = line.replace(
                        "var expiryDate = moment('", ""
                    ).replace(
                        "').format('YYYY-MM-DDTHH:mm:ss Z');", ""
                    )
                    expiration_date = dateutil.parser.parse(
                        str_date, ignoretz=True)

    else:
        for line in str(whois_data).splitlines():
            if line == "":
                continue

            if "Your connection limit exceeded. Please slow down and try again later." in line:
                # Interval is small
                error = 2
                if domain not in ERRORS2_DOMAIN:
                    ERRORS2_DOMAIN.append(str(domain).lower())
                return None, None, None, error

            if any(not_found_string in line for not_found_string in
                   NOT_FOUND_STRINGS):
                # Is it Free?
                return None, None, None, error

            if any(expire_string in line for expire_string in EXPIRE_STRINGS):
                if not expiration_date:
                    try:
                        str_date = str(line.partition(": ")[2])
                        if str_date == "":
                            str_date = str(line.partition("]")[2])
                        str_date = str_date.replace("/", "-")
                        expiration_date = dateutil.parser.parse(
                            str_date, ignoretz=True)
                    except Exception:
                        error = 1

            if any(registrar_string in line for registrar_string in
                   REGISTRAR_STRINGS):
                if not registrar:
                    registrar = line.partition(": ")[2].strip()

            if any(whois_server_string in line for whois_server_string in
                   WHOIS_SERVER_STRINGS):
                if not whois_server:
                    whois_server = line.partition(": ")[2].strip()

    return expiration_date, registrar, whois_server, error


def calculate_expiration_days(expiration_date):
    """
    Check to see when a domain will expire
    :param expiration_date: date
    :return: integer
    """
    try:
        domain_expire = expiration_date - datetime.now()
    except:
        print(f"{FLR}Unable to calculate the expiration days")
        sys.exit(-1)

    return domain_expire.days


def send_expires_dict_telegram():
    """
    Sending a message through the Telegram bot.
    :return: string
    """
    g_total_cost = G_TOTAL_COST_SOON + G_TOTAL_COST_EXPIRE

    if (len(EXPIRES_DOMAIN) == 0) and (len(ERRORS_DOMAIN) == 0) and (len(ERRORS2_DOMAIN) == 0):
        return None

    today = "{:%d.%m.%Y}".format(datetime.now())
    hl = "{:-<42}".format("")

    message = ""
    if len(EXPIRES_DOMAIN) > 0:
        # add expiring domains
        message += "\n<b>Expiring domains</b><pre>" + today + "\n"
        message += hl + "\n"
        for domain, day_left in EXPIRES_DOMAIN.items():
            dn = "{:<42}".format(domain)
            str_domain_item = dn + " : " + str(day_left) + "\n"
            message += str_domain_item
        message += "</pre>"

    if len(ERRORS_DOMAIN) > 0:
        # add error domains
        message += "\n<b>Domains that caused errors</b><pre>" + today + "\n"
        message += hl + "\n"
        for domain in ERRORS_DOMAIN:
            dn = "{:<42}".format(domain)
            str_domain_item = dn + " : -\n"
            message += str_domain_item
        message += "</pre>"

    if len(ERRORS2_DOMAIN) > 0:
        # add error2 domains
        message += "\n<b>Exceeded the limit on whois</b><pre>" + today + "\n"
        message += hl + "\n"
        for domain in ERRORS2_DOMAIN:
            dn = "{:<42}".format(domain)
            str_domain_item = dn + " : -\n"
            message += str_domain_item
        message += "</pre>"

    if g_total_cost > 0:
        message += "\n<b>Cost</b><pre>"
        message += hl + "\n"
        if G_TOTAL_COST_EXPIRE > 0:
            message += "For Expires   : " + G_CURRENCY_SYMBOL + " " + str(round(G_TOTAL_COST_EXPIRE, 2)) + "\n"
        if G_TOTAL_COST_SOON > 0:
            message += "For Soon      : " + G_CURRENCY_SYMBOL + " " + str(round(G_TOTAL_COST_SOON, 2)) + "\n"
        message += hl + "\n"
        message += "Total         : " + G_CURRENCY_SYMBOL + " " + str(round(g_total_cost, 2)) + "\n"
        message += "</pre>"

    if message != "":
        message += "\n"

    response = send_telegram(message)
    return response


def send_telegram(message):
    """
    Sending a message through the Telegram bot.
    :param message: string
    :return: string
    """
    params = {'chat_id': TELEGRAM_CHAT_ID, 'parse_mode': 'html', 'text': message}
    if len(TELEGRAM_PROXIES) > 0:
        response = requests.post(TELEGRAM_URL + 'sendMessage', data=params, proxies=TELEGRAM_PROXIES,
                                 headers=REQUEST_HEADERS)
    else:
        response = requests.post(TELEGRAM_URL + 'sendMessage', data=params,
                                 headers=REQUEST_HEADERS)
    return response


def send_expires_dict_email():
    """
    Preparing the contents of an email to send.
    :return: None
    """
    g_total_cost = G_TOTAL_COST_SOON + G_TOTAL_COST_EXPIRE

    if (len(EXPIRES_DOMAIN) == 0) and (len(ERRORS_DOMAIN) == 0) and (len(ERRORS2_DOMAIN) == 0):
        return

    msg = MIMEMultipart("alternative")
    msg['From'] = SMTP_SENDER
    msg['To'] = CLI.email_to
    msg['Subject'] = "Expiring domains"

    body_text = "Expiring domains\n%BODY%"
    body_html = """\
    <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
    <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    </head>
    <html>
      <body marginwidth="0" \
      marginheight="0" leftmargin="0" topmargin="0" style="background-color:#F6F6F6; \
      font-family:Arial,serif; margin:0; padding:0; min-width: 100%; \
      -webkit-text-size-adjust:none; -ms-text-size-adjust:none;">
        <div style="width: auto; color:#fff; background-color: #C70039; \
        padding: 50px; display: inline-block;">
        %BODY%
        </div>
      </body>
    </html>
    """

    today = "{:%d.%m.%Y}".format(datetime.now())
    hl = "{:-<42}".format("")

    # For part plain
    domain_list_txt = ""
    if len(EXPIRES_DOMAIN) > 0:
        # add expiring domains
        domain_list_txt += "\nExpiring domains\n"
        domain_list_txt += today + "\n"
        domain_list_txt += hl + "\n"
        i = 0
        for domain, day_left in EXPIRES_DOMAIN.items():
            i += 1
            dn = "{:<42}".format(domain)
            str_domain_item = str(i) + ". " + dn + " " + str(day_left) + "\n"
            domain_list_txt += str_domain_item

    if len(ERRORS_DOMAIN) > 0:
        # add error domains
        domain_list_txt += "\nDomains that caused errors\n"
        domain_list_txt += today + "\n"
        domain_list_txt += hl + "\n"
        for i, domain in enumerate(ERRORS_DOMAIN, 1):
            dn = "{:<42}".format(domain)
            str_domain_item = str(i) + ". " + dn + " -\n"
            domain_list_txt += str_domain_item

    if len(ERRORS2_DOMAIN) > 0:
        # add error2 domains
        domain_list_txt += "\nExceeded the limit on whois\n"
        domain_list_txt += today + "\n"
        domain_list_txt += hl + "\n"
        for i, domain in enumerate(ERRORS2_DOMAIN, 1):
            dn = "{:<42}".format(domain)
            str_domain_item = str(i) + ". " + dn + " -\n"
            domain_list_txt += str_domain_item

    if g_total_cost > 0:
        domain_list_txt += "\nCost\n"
        domain_list_txt += hl + "\n"
        if G_TOTAL_COST_EXPIRE > 0:
            domain_list_txt += "For Expires   : " + G_CURRENCY_SYMBOL + " " + str(round(G_TOTAL_COST_EXPIRE, 2)) + "\n"
        if G_TOTAL_COST_SOON > 0:
            domain_list_txt += "For Soon      : " + G_CURRENCY_SYMBOL + " " + str(round(G_TOTAL_COST_SOON, 2)) + "\n"
        domain_list_txt += hl + "\n"
        domain_list_txt += "Total         : " + G_CURRENCY_SYMBOL + " " + str(round(g_total_cost, 2)) + "\n"
        domain_list_txt += "\n"

    body_text = body_text.replace("%BODY%", domain_list_txt)

    # For part html
    domain_list = ""
    if len(EXPIRES_DOMAIN) > 0:
        # add expiring domains
        domain_list += "<br><b>Expiring domains</b><br><pre>"
        domain_list += today + "\n"
        domain_list += hl + "\n"
        i = 0
        for domain, day_left in EXPIRES_DOMAIN.items():
            i += 1
            dn = "{:<42}".format(domain)
            str_domain_item = str(i) + ". " + dn + " " + str(day_left) + "\n"
            domain_list += str_domain_item
        domain_list += "</pre>"

    if len(ERRORS_DOMAIN) > 0:
        # add error domains
        domain_list += "<br><b>Domains that caused errors</b><br><pre>"
        domain_list += today + "\n"
        domain_list += hl + "\n"
        for i, domain in enumerate(ERRORS_DOMAIN, 1):
            dn = "{:<42}".format(domain)
            str_domain_item = str(i) + ". " + dn + " -\n"
            domain_list += str_domain_item
        domain_list += "</pre>"

    if len(ERRORS2_DOMAIN) > 0:
        # add error2 domains
        domain_list += "<br><b>Exceeded the limit on whois</b><br><pre>"
        domain_list += today + "\n"
        domain_list += hl + "\n"
        for i, domain in enumerate(ERRORS2_DOMAIN, 1):
            dn = "{:<42}".format(domain)
            str_domain_item = str(i) + ". " + dn + " -\n"
            domain_list += str_domain_item
        domain_list += "</pre>"

    if g_total_cost > 0:
        domain_list += "<br><b>Cost</b><pre>"
        domain_list += hl + "\n"
        if G_TOTAL_COST_EXPIRE > 0:
            domain_list += "For Expires   : " + G_CURRENCY_SYMBOL + " " + str(round(G_TOTAL_COST_EXPIRE, 2)) + "\n"
        if G_TOTAL_COST_SOON > 0:
            domain_list += "For Soon      : " + G_CURRENCY_SYMBOL + " " + str(round(G_TOTAL_COST_SOON, 2)) + "\n"
        domain_list += hl + "\n"
        domain_list += "Total         : " + G_CURRENCY_SYMBOL + " " + str(round(g_total_cost, 2)) + "\n"
        domain_list += "</pre>"

    body_html = body_html.replace("%BODY%", domain_list)

    part_plain = MIMEText(body_text, "plain")
    part_html = MIMEText(body_html, "html")

    msg.attach(part_plain)
    msg.attach(part_html)

    message = msg.as_string()

    send_email(message)


def send_email(message):
    """
    Sending a email to the recipient
    :param message: string
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
        if (CLI.email_auth):
            server.login(SMTP_SENDER, SMTP_PASSWORD)
        server.sendmail(SMTP_SENDER, CLI.email_to, message)
    except Exception as e:
        # Print any error messages to stdout
        print(f"{FLR}{e}")
    finally:
        server.quit()


def process_cli():
    """
    parses the CLI arguments and returns a domain or
        a file with a list of domains etc.
    :return: dict
    """
    parser = argparse.ArgumentParser(
        description="""DNS Domain Expiration Checker
        A simple python script to display or notify a user by email and/or via Telegram
        about the status of the domain and the expiration date.
        """,
        epilog="(c) AK545 (Andrey Klimov) 2019..2020, e-mail: ak545 at mail dot ru",
        add_help=False
    )
    parent_group = parser.add_argument_group(
        title="Options"
    )
    parent_group.add_argument(
        "-h",
        "--help",
        action="help",
        help="Help"
    )
    parent_group.add_argument(
        "-v",
        "--version",
        action="version",
        help="Display the version number",
        version="%(prog)s version: {}".format(__version__)
    )
    parent_group.add_argument(
        "-f",
        "--file",
        help="Path to the file with the list of domains (default is None)",
        metavar="FILE"
    )
    parent_group.add_argument(
        "-d",
        "--domain",
        help="Domain to check expiration on (default is None)",
        metavar="STRING"
    )
    parent_group.add_argument(
        "-c",
        "--print-to-console",
        action="store_true",
        default=False,
        help="Enable console printing (default is False)"
    )
    parent_group.add_argument(
        "-l",
        "--long-format",
        action="store_true",
        default=False,
        help="Enable detailed print in console (default is False)"
    )
    parent_group.add_argument(
        "-i",
        "--interval-time",
        default=60,
        type=int,
        metavar="SECONDS",
        help="Time to sleep between whois queries (in seconds, default is 60)"
    )
    parent_group.add_argument(
        "-x",
        "--expire-days",
        default=60,
        type=int,
        metavar="DAYS",
        help="Expiration threshold to check against (in days, default is 60)"
    )
    parent_group.add_argument(
        "-s",
        "--cost-per-domain",
        default=0.00,
        type=float,
        metavar="FLOAT",
        help="The cost per one domain (in your currency, default is 0.00)"
    )
    parent_group.add_argument(
        "-t",
        "--use-telegram",
        action="store_true",
        default=False,
        help="Send a warning message through the Telegram (default is False)"
    )
    parent_group.add_argument(
        "-p",
        "--proxy",
        help="Proxy link (for Telegram only), for example: socks5://127.0.0.1:9150 (default is None)",
        metavar="URL"
    )
    parent_group.add_argument(
        "-e",
        "--email-to",
        help=" Send a warning message to email address (default is None)",
        metavar="EMAIL"
    )
    parent_group.add_argument(
        "-ssl",
        "--email-ssl",
        action="store_true",
        default=False,
        help="Send email via SSL (default is False)"
    )
    parent_group.add_argument(
        "-auth",
        "--email-auth",
        action="store_true",
        default=False,
        help="Send email via authenticated SMTP (default is False)"
    )
    parent_group.add_argument(
        "-starttls",
        "--email-starttls",
        action="store_true",
        default=False,
        help="Send email via STARTTLS (default is False)"
    )
    parent_group.add_argument(
        "-oe",
        "--use-only-external-whois",
        action="store_true",
        default=False,
        help="Use only external utility whois (default is False)"
    )
    parent_group.add_argument(
        "-ee",
        "--use-extra-external-whois",
        action="store_true",
        default=False,
        help="Use external whois utility for additional analysis (default is False)"
    )
    parent_group.add_argument(
        "-nb",
        "--no-banner",
        action="store_true",
        default=False,
        help="Do not print banner (default is False)"
    )
    return parser


def print_namespase():
    """
    Print preset options to console
    :return: None
    """
    use_internal_whois = True

    if CLI.use_only_external_whois:
        use_internal_whois = False

    print(
        f"\tPreset options\n"
        f"\t-------------------------\n"
        f"\tFile                     : {CLI.file}\n"
        f"\tDomain                   : {CLI.domain}\n"
        f"\tPrint to console         : {CLI.print_to_console}\n"
        f"\tLong Format              : {CLI.long_format}\n"
        f"\tInterval Time            : {CLI.interval_time}\n"
        f"\tExpire Days              : {CLI.expire_days}\n"
        f"\tUse Telegram             : {CLI.use_telegram}\n"
        f"\tProxy for Telegram       : {CLI.proxy}\n"
        f"\tEmail to                 : {CLI.email_to}\n"
        f"\tEmail SSL                : {CLI.email_ssl}\n"
        f"\tEmail AUTH               : {CLI.email_auth}\n" 
        f"\tEmail STARTTLS           : {CLI.email_starttls}\n"
        f"\tUse internal whois       : {use_internal_whois}\n"
        f"\tUse only external whois  : {CLI.use_only_external_whois}\n"
        f"\tUse extra external whois : {CLI.use_extra_external_whois}\n"
        f"\tPrint banner             : {CLI.no_banner}\n"
        f"\t-------------------------"
    )


def print_hr():
    """
    Pretty print a formatted horizontal line on stdout
    :return: None
    """
    dn = "{:-<42}".format("")
    wis = "{:-<40}".format("")
    reg = "{:-<60}".format("")
    exd = "{:-<20}".format("")
    dl = "{:-<17}".format("")

    if CLI.long_format:
        print(
            f"{FLW}{dn}{FR}",
            f"{FLW}{wis}{FR}",
            f"{FLW}{reg}{FR}",
            f"{FLW}{exd}{FR}",
            f"{FLW}{dl}{FR}"
        )
    else:
        print(
            f"{FLW}{dn}{FR}",
            f"{FLW}{exd}{FR}",
            f"{FLW}{dl}{FR}"
        )


def print_heading():
    """
    Pretty print a formatted heading on stdout
    :return: None
    """
    dn = "{:<42}".format("Domain Name")
    wis = "{:<40}".format("Whois server")
    reg = "{:<60}".format("Registrar")
    exd = "{:<20}".format("Expiration Date")
    dl = "{:<17}".format("Days Left")

    print_hr()

    if CLI.long_format:
        print(
            f"{FLW}{dn}{FR}",
            f"{FLW}{wis}{FR}",
            f"{FLW}{reg}{FR}",
            f"{FLW}{exd}{FR}",
            f"{FLW}{dl}{FR}"
        )
    else:
        print(
            f"{FLW}{dn}{FR}",
            f"{FLW}{exd}{FR}",
            f"{FLW}{dl}{FR}"
        )
    print_hr()


def print_domain(domain, whois_server, registrar, expiration_date, days_remaining, expire_days, cost,
                 current_domain=None, error=None):
    """
    Pretty print the domain information on stdout
    :param domain: string
    :param whois_server: string
    :param registrar: string
    :param expiration_date: date
    :param days_remaining: integer
    :param expire_days: integer
    :param cost: float
    :param current_domain: string
    :param error: integer
    :return: None
    """
    global G_DOMAINS_VALID
    global G_DOMAINS_SOON
    global G_DOMAINS_EXPIRE
    global G_DOMAINS_ERROR
    global G_TOTAL_COST_EXPIRE
    global G_TOTAL_COST_SOON

    if not domain:
        domain = "-"
    else:
        domain = str(domain).strip()

    if not whois_server:
        whois_server = "-"
    else:
        whois_server = str(whois_server).strip()

    if not registrar:
        registrar = "-"
    else:
        registrar = str(registrar).strip()

    dn = "{:<35}".format(str(domain).lower())
    wis = "{:<40}".format(whois_server)
    reg = "{:<60}".format(registrar)

    if not expiration_date:
        exd = "{:<20}".format("-")
    else:
        # exd = "{:%d.%m.%Y %H:%M}    ".format(expiration_date)
        # exd = "{:%d.%m.%Y      }    ".format(expiration_date)
        exd = "{:%Y-%m-%d      }    ".format(expiration_date)

    dl = "{:>4}".format(days_remaining)

    if error == 11:
        dlerr1 = "{:<17}".format("Is it Free!")
    else:
        dlerr1 = "{:<17}".format("Error")

    dlerr2 = "{:<17}".format("Is it Free?")

    # Your connection limit exceeded.
    # Please slow down and try again later.
    dlerr3 = "{:<17}".format("Interval is small")

    if days_remaining == -1 or error:
        if error == 2:
            dnn = f'{FLR}{dn}{FR}'
            ddl = f"{FLR}{dlerr3}{FR}"
        else:
            if error == 11:
                dnn = f'{FLC}{dn}{FR}'
                ddl = f"{FLC}{dlerr1}{FR}"
            else:
                dnn = f'{FLR}{dn}{FR}'
                ddl = f"{FLR}{dlerr1}{FR}"

        G_DOMAINS_ERROR += 1
    elif days_remaining == -2:
        dnn = f'{FLC}{dn}{FR}'
        ddl = f"{FLC}{dlerr2}{FR}"
    elif days_remaining < expire_days:
        dnn = f'{FLR}{dn}{FR}'
        ddl = f"{FLR}Expires    {FR}({dl}){FR}"
        G_DOMAINS_EXPIRE += 1
        G_TOTAL_COST_EXPIRE += cost
    else:
        if days_remaining < (expire_days + G_SOON_ADD):
            dnn = f'{FLY}{dn}{FR}'
            ddl = f"{FLY}Soon       {FR}({dl}){FR}"
            G_DOMAINS_SOON += 1
            G_TOTAL_COST_SOON += cost
        else:
            dnn = f'{FLG}{dn}{FR}'
            ddl = f"{FLG}Valid      {FR}({dl}){FR}"
            G_DOMAINS_VALID += 1

    if not current_domain:
        current_domain = ""

    number_domain = "{:>5}".format(current_domain)
    dnn = "{:<42}".format(number_domain + ". " + dnn)

    if CLI.long_format:
        print(
            dnn,
            f"{wis}",
            f"{reg}",
            f"{exd}",
            ddl
        )
    elif CLI.print_to_console:
        print(
            dnn,
            f"{exd}",
            ddl
        )
    if error == 22:
        # denic.de
        print(
            f"\tThe DENIC whois service on port 43 doesn't disclose any information concerning\n"
            f"\tthe domain holder, general request and abuse contact.\n"
            f"\tThis information can be obtained through use of our web-based whois service\n"
            f"\tavailable at the DENIC website:\n"
            f"\thttp://www.denic.de/en/domains/whois-service/web-whois.html"
        )


def print_stat():
    """
    Print stat to console
    :return: None
    """
    print(
        f"The Result\n"
        f"---------------\n"
        f"Total         : {FLW}{G_DOMAINS_TOTAL}{FR}\n"
        f"Valid         : {FLG}{G_DOMAINS_VALID}{FR}\n"
        f"Soon          : {FLY}{G_DOMAINS_SOON}{FR}\n"
        f"Expires       : {FLR}{G_DOMAINS_EXPIRE}{FR}\n"
        f"Errors        : {FLR}{G_DOMAINS_ERROR}{FR}"
    )
    g_total_cost = G_TOTAL_COST_SOON + G_TOTAL_COST_EXPIRE
    if g_total_cost > 0:
        print(f"---------------")
        print(f"Cost:")
        print(f"---------------")
        if G_TOTAL_COST_SOON > 0:
            print(f"For Soon      : {FLY}{G_CURRENCY_SYMBOL} {round(G_TOTAL_COST_SOON, 2)}")
        if G_TOTAL_COST_EXPIRE > 0:
            print(f"For Expires   : {FLR}{G_CURRENCY_SYMBOL} {round(G_TOTAL_COST_EXPIRE, 2)}")
        print(f"---------------")
        print(f"Total         : {FLW}{G_CURRENCY_SYMBOL} {round(g_total_cost, 2)}")
        print(f"---------------")
        print(f"")


def check_domain(domain_name, expiration_days, cost, interval_time=None, current_domain=0):
    """
    Check domain
    :param domain_name: string
    :param expiration_days: integer
    :param cost: float
    :param interval_time: integer
    :param current_domain: integer
    :return: False - Error, True - Successfully
    """
    global EXPIRES_DOMAIN
    global ERRORS_DOMAIN
    global ERRORS2_DOMAIN

    is_internal_error = False
    if not interval_time:
        interval_time = CLI.interval_time

    expiration_date = None
    registrar = None
    whois_server = None
    error = None

    if CLI.use_only_external_whois:
        expiration_date, registrar, whois_server, error = make_whois_query(
            domain_name)
    else:
        w = None
        try:
            w = whois.whois(domain_name)
        except Exception as e:
            is_internal_error = True
            error = 1

        if not is_internal_error:
            is_internal_error = w is None

        if not is_internal_error:
            expiration_date = w.get("expiration_date")
            registrar = w.get("registrar")
            whois_server = w.get("whois_server")

            is_internal_error = expiration_date is None

        if is_internal_error:
            if CLI.use_extra_external_whois:
                expiration_date_e, registrar_e, whois_server_e, error = make_whois_query(
                    domain_name)
                if error:
                    if error == 1:
                        if domain_name not in ERRORS_DOMAIN:
                            ERRORS_DOMAIN.append(str(domain_name).lower())
                    elif error == 2 or error == 22:
                        # Exceeded the limit on whois
                        if domain_name not in ERRORS2_DOMAIN:
                            ERRORS2_DOMAIN.append(str(domain_name).lower())
                if not expiration_date:
                    expiration_date = expiration_date_e
                if not registrar:
                    registrar = registrar_e
                if not whois_server:
                    whois_server = whois_server_e
            else:
                if domain_name not in ERRORS_DOMAIN:
                    ERRORS_DOMAIN.append(str(domain_name).lower())
                print_domain(domain_name, None, None, None, -1, -1, cost, current_domain, error)  # Error
                if current_domain < G_DOMAINS_TOTAL:
                    if interval_time:
                        if CLI.print_to_console:
                            print(f"\tWait {interval_time} sec...\r", end="")
                        time.sleep(interval_time)
                return False

    if (not whois_server) and (not registrar) and (not expiration_date):
        print_domain(domain_name, whois_server, registrar,
                     expiration_date, -2, -1, cost, current_domain, error)  # Free ?
        if current_domain < G_DOMAINS_TOTAL:
            if interval_time:
                if CLI.print_to_console:
                    print(f"\tWait {interval_time} sec...\r", end="")
                time.sleep(interval_time)
        return False

    if not expiration_date:
        print_domain(domain_name, whois_server, registrar,
                     expiration_date, -1, -1, cost, current_domain, error)  # Error
        if current_domain < G_DOMAINS_TOTAL:
            if interval_time:
                if CLI.print_to_console:
                    print(f"\tWait {interval_time} sec...\r", end="")
                time.sleep(interval_time)
        return False

    if 'datetime.datetime' in str(type(expiration_date)):
        expiration_date_min = expiration_date
    else:
        expiration_date_min = max(expiration_date)

    days_remaining = calculate_expiration_days(expiration_date_min)

    print_domain(domain_name, whois_server, registrar, expiration_date_min, days_remaining,
                 expiration_days, cost, current_domain, error)

    if days_remaining < expiration_days:
        EXPIRES_DOMAIN[str(domain_name).lower()] = days_remaining

    return True


def prepaire_domains_list(file):
    """
    Prepare Domains List from file
    :param file: string
    :return: None
    """
    global G_DOMAINS_LIST
    global G_DOMAINS_TOTAL

    G_DOMAINS_TOTAL = 0
    domain_dict = {}
    G_DOMAINS_LIST = []

    with open(file, "r", encoding="utf-8", newline="\n") as domains_to_process:
        i = 0
        for line in domains_to_process:
            domain_dict.clear()

            domain_dict.update({
                "group": "",
                "domain": "",
                "expire_days": -1,
                "interval_time": CLI.interval_time,
                "cost": CLI.cost_per_domain,
            })

            try:
                ss = line.strip()
                if len(ss) == 0:
                    continue

                if len(ss) > 0:
                    if ss.lstrip().startswith("!"):
                        # the group header
                        i += 1
                        header = ss.partition("!")[2].strip()

                        domain_dict["group"] = header
                        domain_dict["domain"] = ""
                        domain_dict["expire_days"] = -1
                        domain_dict["interval_time"] = -1
                        domain_dict["cost"] = 0.00
                        G_DOMAINS_LIST.append(domain_dict.copy())
                        continue

                    if ss.lstrip().startswith("#"):
                        # the comment
                        continue

                    # the domain?
                    word_list = ss.lower().split()
                    if len(word_list) > 0:
                        domain_name = word_list[0].strip()
                        if (":" in domain_name) or (domain_name.isdigit()):
                            # Broken line, this is not domain
                            continue

                        domain_dict["domain"] = domain_name
                        G_DOMAINS_TOTAL += 1

                        if len(word_list) > 1:
                            # If the string contains the interval value in
                            # seconds and/or the expiration value in days
                            for i, item in enumerate(word_list):
                                if i == 0:
                                    # domain name - skip
                                    continue

                                if "sleep:" in item:
                                    # the interval value in seconds
                                    interval_time = int(
                                        str(item).partition("sleep:")[2].strip())
                                    domain_dict["interval_time"] = interval_time
                                elif "cost:" in item:
                                    # the cost of this domain
                                    cost = float(
                                        str(item).partition("cost:")[2].strip())
                                    domain_dict["cost"] = cost
                                else:
                                    # the expiration value in days
                                    domain_dict["expire_days"] = int(item)
                        else:
                            domain_dict["expire_days"] = CLI.expire_days

                        G_DOMAINS_LIST.append(domain_dict.copy())

            except Exception:
                err = "Unable to parse the file with the list of domains.\nProblem line\n\"%s\"" % line.strip()
                print(f"{FLR}{err}")
                sys.exit(1)


def check_cli_logic():
    """
    Check command line logic
    :return: None
    """
    global CLI
    global TELEGRAM_PROXIES

    if CLI.print_to_console and not CLI.no_banner:
        # Print banner
        if platform.platform().startswith('Windows'):
            home_path = os.path.join(os.getenv('HOMEDRIVE'),
                                     os.getenv('HOMEPATH'))
        else:
            home_path = os.path.join(os.getenv('HOME'))
        print(
            f"\tPython  : {FLC}{sys.version}{FR}\n"
            f"\tNode    : {FLC}{platform.node()}{FR}\n"
            f"\tHome    : {FLC}{home_path}{FR}\n"
            f"\tOS      : {FLC}{platform.system()}{FR}\n"
            f"\tRelease : {FLC}{platform.release()}{FR}\n"
            f"\tVersion : {FLC}{platform.version()}{FR}\n"
            f"\tArch    : {FLC}{platform.machine()}{FR}\n"
            f"\tCPU     : {FLC}{platform.processor()}{FR}"
        )
        print_namespase()

    if CLI.use_only_external_whois or CLI.use_extra_external_whois:
        whois_check()

    if CLI.use_only_external_whois and CLI.use_extra_external_whois:
        print(
            f"{FLR}One of the parameters is superfluous. "
            f"Use either --use-only-external-whois or --use-extra-external-whois"
        )
        sys.exit(-1)

    if CLI.long_format and (not CLI.print_to_console):
        CLI.print_to_console = True

    if (not CLI.print_to_console and (CLI.file or CLI.domain)) and (
            (not CLI.use_telegram) and (not CLI.email_to)):
        print(
            f"{FLR}You must use at least one of the notification methods "
            f"(email, telegram or console)\n"
            f"Use --print-to-console or --use-email or/and --use-telegram"
        )
        sys.exit(-1)

    if CLI.email_ssl and (not CLI.email_to):
        print(
            f"{FLR}You must specify the email address of the recipient. Use the --email_to option")
        sys.exit(-1)

    if CLI.email_auth and (not CLI.email_to):
        print(
            f"{FLR}You must specify the email address of the recipient. Use the --email_to option")
        sys.exit(-1)

    if CLI.email_starttls and (not CLI.email_to):
        print(
            f"{FLR}You must specify the email address of the recipient. Use the --email_to option")
        sys.exit(-1)

    if CLI.email_starttls and CLI.email_ssl and CLI.email_to:
        print(f"{FLR}The contradiction of options. You must choose one thing: either --email-ssl or "
              f"--email-starttls or do not use either one or the other")
        sys.exit(-1)

    if CLI.file and CLI.domain:
        print(
            f"{FLR}One of the parameters is superfluous. Use either --file or --domain")
        sys.exit(-1)

    if CLI.proxy and (not CLI.use_telegram):
        print(f"{FLR}The proxy setting is for telegram only")
        sys.exit(-1)

    if CLI.proxy and CLI.use_telegram:
        TELEGRAM_PROXIES.clear()
        TELEGRAM_PROXIES['http'] = CLI.proxy
        TELEGRAM_PROXIES['https'] = CLI.proxy

    if CLI.print_to_console:
        print_heading()


def main():
    """
    Main function
    :return: None
    """
    global EXPIRES_DOMAIN
    global ERRORS_DOMAIN
    global ERRORS2_DOMAIN

    # Check command line logic
    check_cli_logic()

    EXPIRES_DOMAIN = {}
    ERRORS_DOMAIN = []
    ERRORS2_DOMAIN = []

    if CLI.file:
        # Source data from file
        file = str(CLI.file).strip()
        if not Path(file).is_file():
            print(f"{FLR}File {FLY}{file}{FLR} not found")
            sys.exit(-1)

        # Prepaire domains list
        prepaire_domains_list(CLI.file)

        if G_DOMAINS_TOTAL > 0:
            i = 0
            current_domain = 0

            for item in G_DOMAINS_LIST:
                expiration_days = CLI.expire_days
                group = item["group"]
                domain = item["domain"]
                expire_days = item["expire_days"]
                interval_time = item["interval_time"]
                cost = item["cost"]

                if group != "":
                    i += 1
                    si = "{:>4}".format(i)
                    if i == 1:
                        if CLI.print_to_console:
                            print(f"{si}. {FLW}{group}")
                    else:
                        if CLI.print_to_console:
                            print(f" " * 40, end="")
                            print(f"\n{si}. {FLW}{group}")
                    continue

                if expire_days > 0:
                    expiration_days = expire_days

                if interval_time == -1:
                    interval_time = None

                if domain != "":
                    current_domain += 1
                    domain_name = domain

                    # Domain Check
                    if not check_domain(domain_name, expiration_days, cost, interval_time, current_domain):
                        # If error - skip
                        continue

                    # Need to wait between queries to avoid triggering DOS measures like so:
                    # Your IP has been restricted due to excessive access, please wait a bit
                    if current_domain < G_DOMAINS_TOTAL:
                        if interval_time:
                            if CLI.print_to_console:
                                print(
                                    f"\tWait {interval_time} sec...\r",
                                    end=""
                                )
                            time.sleep(interval_time)

            if CLI.print_to_console:
                print(f"{' '*38}\r", end="")
                print_hr()
                print_stat()
                print(f"Process complete.")
                # if G_DOMAINS_SOON > 0 or G_DOMAINS_EXPIRE > 0 or G_DOMAINS_ERROR > 0:
                #     time.sleep(10)

    elif CLI.domain:
        # Source data - one domain from the command line
        domain_name = CLI.domain
        expiration_days = CLI.expire_days
        cost = CLI.cost_per_domain

        # Domain Check
        check_domain(domain_name, expiration_days, cost, None, 1)

        if CLI.print_to_console:
            print_hr()
            print(f"Process complete.")

    if (len(EXPIRES_DOMAIN) > 0) or (len(ERRORS_DOMAIN) > 0) or (len(ERRORS2_DOMAIN) > 0):
        if CLI.email_to:
            send_expires_dict_email()

        if CLI.use_telegram:
            res = send_expires_dict_telegram()
            if res:
                if res.status_code != 200:
                    print(f"{FLR}{res.text}")


if __name__ == "__main__":
    print(f"{SR}")

    # Parsing command line
    parser = process_cli()
    CLI = parser.parse_args(sys.argv[1:])
    main()
