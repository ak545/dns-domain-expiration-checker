# DNS Domain Expiration Checker from ak545
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)

**ddec.py** - This is a python script to check the expiration dates for the registration of your domains.

This script develops the idea of another [DNS Domain Expiration Checker](https://github.com/Matty9191/dns-domain-expiration-checker), Author: Matty < matty91 at gmail dot com >

## Screenshots
![](https://github.com/ak545/dns-domain-expiration-checker/raw/master/images/script.png)
> Script in working

<details>
<summary>More</summary>

![](https://github.com/ak545/dns-domain-expiration-checker/raw/master/images/script2.png)
> Script in working

![](https://github.com/ak545/dns-domain-expiration-checker/raw/master/images/email.png)
> A sample of the email

![](https://github.com/ak545/dns-domain-expiration-checker/raw/master/images/email2.png)
> A sample of the email

![](https://github.com/ak545/dns-domain-expiration-checker/raw/master/images/telegram.png)
> A sample of the Telegram message

</details>

## Description
If you are here, it is possible that your domain has expired and you have coped with the troubles associated with its restoration. It's not fun, right? To prevent you from getting into a similar situation again, you can install and run **ddec.py** to monitor your domain names. If you add this script to the task scheduler (for example, to cron, if you have Linux or to Task Scheduler, if you have Windows), then it will monitor the timeliness of updating domain names. If the deadline for the registration of your domain names is coming soon, the script will inform you in time about this (either by email or by Telegram or directly in the console). If you own several domain names served by different registrars, this script will also help to standardize all notifications about the expiration of the registration of domain names.

## Installation
The script requires **Python version 3.6 or higher**.
Of course, you need to install it yourself first [Python](https://www.python.org/). On Linux, it is usually already installed. If not, install it, for example:

```console
$ sudo yum install python3
$ sudo dnf install python3
$ sudo apt install python3
$ sudo pacman -S python
```
Additionally, you will need a Python package installer, such as **pip**. You can install it on Linux like this:
```console
$ sudo yum install python3-pip
$ sudo dnf install python3-pip
$ sudo apt install python3-pip
$ sudo pacman -S python-pip
```

For Apple macOS:
```console
$ xcode-select --install
```

Install brew:
```console
$ /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Install Python:

```console
$ export PATH=/usr/local/bin:/usr/local/sbin:$PATH
$ brew install python
```

Note: [brew](https://brew.sh/)

For Microsoft Windows download the [distribution package](https://www.python.org/downloads/windows/) and install it. I recommend downloading "Download Windows x86 executable installer" if you have a 32-bit OS and "Download Windows x86-64 web-based installer" if you have a 64-bit OS. During installation, I recommend checking all options (Documentation, pip, tcl / tk and IDLE, Python test suit, py launcher, for all users (requeres elevation)).

Previously, you may need to update **pip** itself (Python package installer):
```console
$ python -m pip install --upgrade pip
or
> py -m pip install --upgrade pip
```

### Installing and update dependencies
```console
$ pip install -U python-whois
$ pip install -U python-dateutil
$ pip install -U colorama
```
and
```console
$ pip install -U requests[socks]
```    
or
```console
$ pip install -U PySocks
```

If you are running Linux or macOS, and you plan to run the script as the current user, then additionally specify the **--user** option. In this case, the necessary dependencies will be installed into the home folder of the current system user and are available when launched from the task scheduler (cron) on behalf of this current user.

Depending on your Python environment, your actions will be slightly different, for example, you may need to specify the **--user** key (for **pip**) or use the **python3** and **pip3** commands instead of the **python** and **pip** commands. If you use [virtual environments](https://docs.python.org/3/library/venv.html), then most likely, you will need to do all of these actions after entering the appropriate environment.

## Usage
```console
$ ddec.py -h
usage:  ddec.py [Options]

        A simple python script to display or notify a user by email and/or via Telegram
        about the status of the domain and the expiration date.

        DNS Domain Expiration Checker

Options:
  -h, --help            Help
  -v, --version         Display the version number
  -f FILE, --file FILE  Path to the file with the list of domains (default is None)
  -d STRING, --domain STRING
                        Domain to check expiration on (default is None)
  -c, --print-to-console
                        Enable console printing (default is False)
  -l, --long-format     Enable detailed print in console (default is False)
  -i SECONDS, --interval-time SECONDS
                        Time to sleep between whois queries (in seconds, default is 60)
  -x DAYS, --expire-days DAYS
                        Expiration threshold to check against (in days, default is 60)
  -s FLOAT, --cost-per-domain FLOAT
                        The cost per one domain (in your currency, default is 0.00)
  -twtc, --track-whois-text-changes
                        Enable whois text change monitoring (default is False)
  -t, --use-telegram    Send a warning message through the Telegram (default is False)
  -p URL, --proxy URL   Proxy link (for Telegram only), for example: socks5://127.0.0.1:9150 (default is None)
  -e EMAIL, --email-to EMAIL
                        Send a warning message to email address (default is None)
  -subject STRING, --email-subject STRING
                        Append custom text to the email subject (default is None)
  -ssl, --email-ssl     Send email via SSL (default is False)
  -auth, --email-auth   Send email via authenticated SMTP (default is False)
  -starttls, --email-starttls
                        Send email via STARTTLS (default is False)
  -oe, --use-only-external-whois
                        Use only external utility whois (default is False)
  -ee, --use-extra-external-whois
                        Use external whois utility for additional analysis (default is False)
  -nb, --no-banner      Do not print banner (default is False)

© AK545 (Andrey Klimov) 2019..2022, e-mail: ak545 at mail dot ru
```

### Description of options
**-h, --help**

Help

**-v, --version**

Display the version number

**-f FILE, --file FILE**

Path to the file with the list of domains (default is None)

#### File format with a list of domains
```bash
    domain [%days%] [sleep:%seconds%] [cost:%cost%] [skip_checking_whois_text_changes]
    domain [sleep:%seconds%] [%days%]
    domain [%days%]
    domain [sleep:%seconds%]
    domain [cost:%cost%]
    domain
```

**domain** - Domain name

**%days%** - An integer indicating how many days before the expiration of the domain registration to raise an alarm.

**%seconds%** - An integer, the number of seconds to sleep in before analyzing the next domain. The keyword "**sleep:**" does not change. Spaces between this keyword and the number of seconds are not allowed.

**%cost%** - The number that represents the cost of renewing a domain. The keyword "**cost:**" does not change. Spaces between this keyword and cost are not allowed.

**skip_checking_whois_text_changes** - Keyword to ignore possible whois text change checks.


The file must be encoded in **UTF-8 without BOM**, the format of the new line: **Unix (0Ah)**


#### Sample domain list file
```bash
#-------------------------------------------------------------
#
# Example file with the list of domains
# Allowed:
# - blank lines
# - string as comment (the string must begin with the character "#")
# - string as the name of the group header (the string must begin with the character "!")
#
# The format for setting the domain string is:
# - domain name (required first)
# - expiration value in days (integer)
# - interval value in seconds before proceeding to the next check (sleep:integer)
# - the cost of renewing a domain (cost:float)
# - skip checking whois text changes for this domain (skip_checking_whois_text_changes)
#
# For example:
# ! Group 1
# domain_name
# domain_name integer
#
# ! Group 2
# domain_name integer sleep:integer cost:float skip_checking_whois_text_changes
# domain_name sleep:integer integer
# domain_name sleep:integer
#
# If the expiration value in days is not specified,
# the default value is used or from the command line parameter
#
# If the interval value in seconds is not specified before moving on to the next check,
# the default value or from the command line parameter is used.
#
# If the cost of renewing a domain is not specified,
# the default value is used or from the command
# line parameter
#
#-------------------------------------------------------------

! The sample of the group header
a.ru
linux.cafe 1000 sleep:8 cost:20.55
cyberciti.biz sleep:10 70
dotmobi.mobi 80
spotch.com sleep:15
yahoo.com
prefetch.net
nixcraft.com
abc.xyz
codepen.io
habr.com
freepascal.org
mikrotik.com skip_checking_whois_text_changes
git-scm.com
github.com
python.org

! Social networks
livejournal.com
facebook.com
twitter.com

! Youtube
youtube.tv
youtube.com
```

**-d STRING, --domain STRING**

Domain to check expiration on (default is None)

**-c, --print-to-console**

Enable console printing (default is False)
The console prints the columns "Domain Name", "Expiration Date" and "Days Left".

**-l, --long-format**

Enable detailed print in console (default is False)
The console prints the columns "Domain Name", "Whois server", "Registrar", "Expiration Date" and "Days Left".

**-i SECONDS, --interval-time SECONDS**

Time to sleep between whois queries (in seconds, default is 60)

**-x DAYS, --expire-days DAYS**

Expiration threshold to check against (in days, default is 60)
How many days before the expiration of the domain registration start to warn.

**-s FLOAT, --cost-per-domain FLOAT**

The cost of renewing a domain (default is 0.00)

**-twtc, --track-whois-text-changes**

Enable whois text change monitoring (default is False)

If the **skip_checking_whois_text_changes** keyword is specified in a file with a list of domains for a domain, then the check for whois text changes for that domain will be ignored.

**-t, --use-telegram**

Send a warning message through the Telegram (default is False)

**-p URL, --proxy URL**

Proxy link (for Telegram only), for example: socks5://127.0.0.1:9150 (default is None).

**-e EMAIL, --email-to EMAIL**

Send a warning message to email address (default is None)
Here you must specify the email address of the recipient.

**-subject STRING, --email-subject STRING**

Append custom text to the email subject (default is None). This is an additional option for --email-to.

**-ssl, --email-ssl**

Send email via SSL (default is False). This is an additional option for --email-to.

**-auth, --email-auth**

Send email via authenticated SMTP (default is False). This is an additional option for --email-to.

**-starttls, --email-starttls**

Send email via STARTTLS (default is False). This is an additional option for --email-to.

**-oe, --use-only-external-whois**

Use only external utility whois (default is False). In this mode, data analysis by the internal engine is not performed. We completely trust the work of the external utility whois.

**-ee, --use-extra-external-whois**

Use external whois utility for additional analysis (default is False)

I recommend using this mode. In this mode, data analysis is first performed by the internal engine, and in case of errors, it is repeated by the external utility whois.
Why do I recommend this particular mode?
Because in some cases, for example, for domains from the .COM zone, domain management can be delegated to some other regional registrars. And if you buy a domain from a regional registrar, then you will be renewing it from him, but not from the parent registrar. But since data synchronization between regional and parent registrars is not instantaneous (the delay is from several minutes to several hours), if you request whois information using only the external whois utility, you will receive data from the parent registrar. The external whois utility works this way. And if the regional registrar by this time has not yet had time to synchronize their data with the parent, you will receive a false message that the domain is not yet renewed, although in fact everything is already fine with it. The internal script engine allows detecting the fact of delegation of domain management from the parent registrar to the regional one. The internal engine takes information about the period of domain registration from the regional registrar whose data is the most reliable and up-to-date.

**-nb, --no-banner**

Do not print banner (default is False).
Banner is information about the script execution environment: Python version, computer name, OS name, OS release, OS version, architecture, CPU, summary table of preset options and information about the path to the external whois utility.

#### External utility whois
In most Linux operating systems, whois is already available. If not, install it.
For example:

For Ubuntu/Debian:
```console
$ sudo apt update && sudo apt upgrade
$ sudo apt install whois
```

For legacy RPM-Based Linux distributions (RHEL 6.x/RHEL 7.x/CentOS 6.x/CentOS 7.x)
```console
$ sudo yum install jwhois
```

For newer RPM-Based Linux distributions (RHEL 8.x/CentOS 8.x/Fedora 22 and higher/Rocky Linux/Alma Linux):
```console
$ sudo dnf install jwhois
```

For Arch/Manjaro:
```console
$ sudo pacman -S whois
```

For Apple macOS:
```console
$ brew install whois
```
Note: [brew](https://brew.sh/)

For OS Microsoft Windows, it is best to use **cygwin** forks **whois**.

Download and run [cygwin](https://www.cygwin.com/).
During the **cygwin** installation, install the **whois** package. Remember where **cygwin** itself is installed (for example, in folder **c:\cygwin64**).

After installing **cygwin**, open a command prompt with administrator privileges.

Note: use **CMD.exe**, do not use *Powershell* (for it the command is completely different)!

Run the command (*see below*; in Windows 7/8/8.1/10/11 **environment variables** can be changed via the graphical user interface):
```console
> setx /M PATH "c:\cygwin64\bin;%PATH%"
```
Note! For the full work of the utility **whois** from the package **cygwin** files are required (in this repository they are in the **/cygwin64/bin/** folder. Please note that these are versions for 64-bit MS Windows operating system.):

    whois.exe
    cygiconv-2.dll
    cygidn-11.dll
    cygintl-8.dll
    cygwin1.dll

## Global constants in the script

Some options are inside the script. There is no point in putting them in the parameters, since you only need to configure them once, and then successfully forget about them.

You may also set environment variables of the same name for SMTP and TELEGRAM to avoid modifying the script.

### SMTP options
**SMTP_SERVER**

SMTP server address

Samples:

```python
    SMTP_SERVER = os.getenv("SMTP_SERVER", "localhost")
    # SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    # SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.mail.ru')
    # SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.yandex.ru')
```

**SMTP_PORT**

SMTP port

Samples:

```python
    # SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))  # For starttls
    # SMTP_PORT = int(os.getenv("SMTP_PORT", "465"))  # For SSL
    SMTP_PORT = int(os.getenv("SMTP_PORT", "25"))   # Default
```

**SMTP_SENDER**

Email address of the sender

Samples:

```python
    SMTP_SENDER = os.getenv("SMTP_SENDER", "user@gmail.com")
```

**SMTP_PASSWORD**

SMTP password

Samples:

```python
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "P@ssw0rd")
```

### Telegram options
**TELEGRAM_TOKEN**

Token Telegram bot

Samples:

```python
    TELEGRAM_TOKEN = 'NNNNNNNNN:NNNSSSSaaaaaFFFFFEEE3gggggQQWFFFFF01z'
```

**TELEGRAM_CHAT_ID**

Telegram Channel ID

Samples:

```python
    TELEGRAM_CHAT_ID = '-NNNNNNNNN'
```

Get help with Telegram API:
[https://core.telegram.org/bots](https://core.telegram.org/bots)
You can create a bot by talking to Telegram with [**@BotFather**](https://telegram.me/BotFather)

**TELEGRAM_URL**

Telegram API URL

Samples:

```python
    TELEGRAM_URL = "https://api.telegram.org/bot" + TELEGRAM_TOKEN + "/"
```

### External utility whois options
**WHOIS_COMMAND**

The command to run the external utility whois

Samples:

```python
    WHOIS_COMMAND = "whois"
    # WHOIS_COMMAND = "/usr/bin/whois"
    # WHOIS_COMMAND = "c:\\cygwin64\\bin\\whois.exe"
    # WHOIS_COMMAND = r"c:\cygwin64\bin\whois.exe"
```

Note: Do not use the similar whois utility from author Mark Russinovich for Microsoft Windows.
When sending whois requests to some whois servers (for example, to GoDaddy.com servers), it may hang or return an incorrect result.


**WHOIS_COMMAND_TIMEOUT**

The maximum waiting time for the output from the external utility whois (in seconds). After this time, the external whois process will be forcibly terminated. The script itself will continue its work.

```python
    WHOIS_COMMAND_TIMEOUT = 10
```

### The cost of domain renewal
**G_CURRENCY_SYMBOL**

Sets the national currency symbol

Samples:

```python
    # G_CURRENCY_SYMBOL = '$'
    G_CURRENCY_SYMBOL = '¥'
    # G_CURRENCY_SYMBOL = '£'
    # G_CURRENCY_SYMBOL = '€'
    # G_CURRENCY_SYMBOL = '₽'
```

### Parameters for estimating the time until the expiration of domain registration
**G_SOON_ADD**

How many days should remain until the end of the domain registration, when the expiration date can be judged as “very soon”, but still valid.
These days are added to the --expire-days parameter (or to the same value in the file of domain name lists)

Samples:

```python
    G_SOON_ADD = 21
```

If --expire-days (or a similar value in the file of domain name lists) is 60 days, then 81 days before the end of the domain registration period (60 + 21), this domain will be in the "Soon" category.

## How to add a script to Linux cron
To do this, create a **crontab** task that will be executed, for example, every midnight on behalf of the user (creating tasks as root is not the best idea):

Suppose your Linux username is: **user**

Your home folder: **/home/user**

The folder where this script is located: **/home/user/py**

To run the script directly, run the command:
```console
$ chmod +x /home/user/py/ddec.py
```

Adjust in the first line of the script [Shebang (Unix)](https://en.wikipedia.org/wiki/Shebang_(Unix)), eg:

Show the path where python is located:
```console
$ which python
```
or
```console
$ which python3
```
Correction python path in Shebang:

```python
#!/usr/bin/python
#!/usr/bin/python3
#!/usr/bin/env python
#!/usr/bin/env python3
```

Rename script:

```console
$ mv /home/user/py/ddec.py /home/user/py/ddec
```
Check script launch:

```console
$ /home/user/py/ddec -h
$ /home/user/py/./ddec -h
```
If everything is fine, run the editor **crontab**, if not, go back to setting **Shebang**:

```console
$ crontab -u user -e
```
Here **user** - is your Linux login

If you, like me, do not like vim (I have not seen a single person who is fluent in this editor, although it probably exists somewhere), you can edit the tasks in your favorite editor, for example:

```console
$ EDITOR=nano crontab -u user -e
$ EDITOR=mcedit crontab -u user -e
```
or

```console
$ VISUAL=nano crontab -u user -e
$ VISUAL=mcedit crontab -u user -e
```

In the task editor, create something like this (do not use keys **--print-to-console** and **--long-format**):

`0 0 * * * /home/user/py/ddec -nb -f /home/user/data/domains0.txt -twtc -i 5 -t -e user@gmail.com -ee >/dev/null 2>&1`

or

`0 0 * * * /home/user/py/./ddec -nb -f /home/user/data/domains0.txt -twtc -i 5 -t -e user@gmail.com -ee >/dev/null 2>&1`


Specify the full paths to the data file and the script.

Note: [cron](https://en.wikipedia.org/wiki/Cron)

You can view created tasks for user **user** like this:

```console
$ crontab -u user -l
```
Delete all tasks from user **user**, you can:

```console
$ crontab -u user -r
```
## How to add a script to Microsoft Windows Task Scheduler
Ask for help to [documentation](https://docs.microsoft.com/en-us/windows/desktop/taskschd/schtasks)

**Sample:**

`> schtasks /Create /SC DAILY /TN "Domain Expiration Checker" /TR "'с:\ddec.py' -nb -twtc -t -e my@email.com -ee -f 'c:\domains.txt'" /ST 23:59`

## Thanks
To the author of the original script: Matty < matty91 at gmail dot com > [https://github.com/Matty9191](https://github.com/Matty9191)

Special thanks for various suggestions and comments:
- [Carl Mercier](https://github.com/cmer)
- [Leif](https://github.com/akhepcat)
- [woodholly](https://github.com/woodholly)

## License
[GNU General Public License v3.0](https://choosealicense.com/licenses/gpl-3.0/)

Why it's like this I don't know.

## Restrictions
I, the author of this python script, wrote this script exclusively for my needs. No warranty is provided. You can use this script freely, without any deductions, for any purpose other than [Cybersquatting](https://en.wikipedia.org/wiki/Cybersquatting).

You can make any changes to the script code and fork this script, provided that the link to me and [Matty](https://github.com/Matty9191) is indicated as a source of your inspiration.

## Postscriptum
- The script was tested in Microsoft Windows 10/11, Linux Fedora 29/30/31/32/33/34/35/36, Linux Debian 9/10/11, Linux Ubuntu Desktop 18.04/20.04/20.10/22.04, Linux CentOS 6/7/8, Rocky Linux 8.6/9.0, Linux Manjaro 18.0.2/20.2/21.3.3, Apple macOS 12.4 Monterey on MacBook Pro M1.

![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Fedora](https://img.shields.io/badge/Fedora-294172?style=for-the-badge&logo=fedora&logoColor=white)
![Debian](https://img.shields.io/badge/Debian-D70A53?style=for-the-badge&logo=debian&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![Cent OS](https://img.shields.io/badge/cent%20os-002260?style=for-the-badge&logo=centos&logoColor=F0F0F0)
![Rocky Linux](https://img.shields.io/badge/-Rocky%20Linux-%2310B981?style=for-the-badge&logo=rockylinux&logoColor=white)
![Manjaro](https://img.shields.io/badge/Manjaro-35BF5C?style=for-the-badge&logo=Manjaro&logoColor=white)
![macOS](https://img.shields.io/badge/mac%20os-000000?style=for-the-badge&logo=macos&logoColor=F0F0F0)

- Sorry for my bad English. And on the other hand, which of you can boast of knowing the great and mighty Russian language? Have any of you read Pushkin, Tolstoy, Dostoyevsky, Gogol, Bulgakov in the original...? It's a joke.
- The program code of the script is not perfect. But please forgive me for that.
- Glory to the E = mc &sup2; !
- I wish you all good luck!

## A final plea
It's time to put an end to Facebook. Working there is not ethically neutral: every day that you go into work, you are doing something wrong. If you have a Facebook account, delete it. If you work at Facebook, quit.

And let us not forget that the National Security Agency must be destroyed.

*(c) [David Fifield](mailto:david@bamsoftware.com)*

---

> Best regards, ak545 ( ru.mail&copy;ak545&sup2; )