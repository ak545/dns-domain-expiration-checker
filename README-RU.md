# DNS Domain Expiration Checker from ak545
**ddec.py** - Это python-скрипт для проверки сроков окончания регистрации ваших доменов.

Этот скрипт развивает идею другого скрипта [DNS Domain Expiration Checker](https://github.com/Matty9191/dns-domain-expiration-checker), Автор: Matty < matty91 at gmail dot com >

## Скриншоты
![](https://github.com/ak545/dns-domain-expiration-checker/raw/master/images/script.png)
> Скрипт в работе

![](https://github.com/ak545/dns-domain-expiration-checker/raw/master/images/email.png)
> Пример email

![](https://github.com/ak545/dns-domain-expiration-checker/raw/master/images/telegram.png)
> Пример Telegram сообщения


## Описание
Если вы находитесь здесь, возможно, у вас истек срок действия домена, и вы справились с неприятностями, связанными с его восстановлением. Это не весело, правда? Чтобы вам снова не попасть в подобную ситуацию, вы можете установить и запустить **ddec.py** для мониторинга ваших доменных имен. Если вы добавите этот скрипт в планировщик заданий (например, в cron, если у вас Linux или в Task Scheduler, если у вас Windows), то он будет следить за своевременностью обновления доменных имен. Если скоро наступят сроки окончания регистрации ваших доменных имен, скрипт вовремя сообщит вам об этом (или по электронной почте или по Telegram или непосредственно в консоли). Если вы владеете несколькими доменными именами, обслуживаемые различными регистраторами, этот скрипт так же поможет стандартизировать все уведомления об истечении сроков регисрации доменных имен.

## Инсталляция
Для работы скрипта необходим **Python версии 3.6 или выше**.
Разумеется, необходимо сперва установить сам [Python](https://www.python.org/). В Linux он обычно уже установлен. Если нет, установите его, например:

```console
$ sudo yum install python3
$ sudo dnf install python3
$ sudo apt install python3
$ sudo pacman -S python
```

Для Apple macOS:
    
```console
$ xcode-select --install
```

Установите brew:

```console
$ /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

Установите Python:

```console
$ export PATH=/usr/local/bin:/usr/local/sbin:$PATH
$ brew install python
```

Примечание: [brew](https://brew.sh/index_ru)

Для Microsoft Windows скачайте [дистрибутив](https://www.python.org/downloads/windows/) и установите его. Я рекомендую скачивать "Download Windows x86 executable installer" если у вас 32-х битная ОС и "Download Windows x86-64 web-based installer" если у вас 64-х битная ОС. Во время установки рекомендую отметить все опции (Documentation, pip, tcl/tk and IDLE, Python test suit, py launcher, for all users (requeres elevation)).

Предварительно, возможно понадобится обновить сам **pip** (установщик модулей Python):

```console
$ python -m pip install --upgrade pip
```

### Установка и обновление зависимостей
```console
$ pip install -U python-whois
$ pip install -U python-dateutil
$ pip install -U colorama
```
и
```console
$ pip install -U requests[socks]
```
или
```console
$ pip install -U PySocks
```
Если Вы работаете под управлением Linux или macOS, и запуск скрипта планируете производить от имени текущего пользователя, то дополнительно указывайте опцию **--user**. В этом случае необходимые зависимости будут устанавливаться в домашнюю папку текущего пользователя системы и доступны при запуске из планировщика задач (cron) от имени этого текущего пользователя.

В зависимости от вашего Pyton окружения, ваши действия будут немного иными, например, возможно, вам потребуется указать ключ **--user** (для **pip**) или вместо команд **python** и **pip** использовать команды **python3** и **pip3**. Если вы используете [виртуальные окружения](https://docs.python.org/3/library/venv.html), то скорее всего, все эти действия вам необходимо будет сделать после входа в соответствующее окружение.

## Использование
```console
$ ddec.py -h
usage: ddec.py [-h] [-v] [-f FILE] [-d STRING] [-c] [-l] [-i SECONDS]
[-x DAYS] [-s FLOAT] [-t] [-p URL] [-e EMAIL] [-subject STRING] [-ssl]
[-auth] [-starttls] [-oe] [-ee] [-nb]

DNS Domain Expiration Checker A simple python script to display or notify a 
user by email and/or via Telegram about the status of the domain and the 
expiration date.

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
```

### Описание опций
**-h, --help**

Помощь

**-v, --version**
    
Показать номер версии

**-f FILE, --file FILE**

Путь к файлу со списком доменов (по умолчанию Нет)

#### Формат файла со списком доменов
```bash
    domain [%days%] [sleep:%seconds%] [cost:%cost%]
    domain [sleep:%seconds%] [%days%]
    domain [%days%]
    domain [sleep:%seconds%]
    domain [cost:%cost%]
    domain
```

**domain** - Имя домена

**%days%** - Целое число, обозначающее за какое количество дней до истечения срока регистрации домена поднимать тревогу.

**%seconds%** - Целое число, количество секунд, на которое необходимо заснуть, перед тем, как продолжить анализ следующего домена. Ключевое слово "**sleep:**" не менять. Пробелы между этим ключевым словом и количеством секунд не допускаются.

**%cost%** - Число, обозначающее стоимость продления домена. Ключевое слово "**cost:**" не менять. Пробелы между этим ключевым словом и стоимостью не допускаются.

Файл должен быть в кодировке **UTF-8 без ВОМ**, формат новой строки: **Unix (0Ah)**

#### Пример файла со списком доменов
```bash
#-------------------------------------------------------------
#
# Пример файла со списком доменов
# Допускается:
# - пустые строки
# - строка - комментарий
# (строка должна начинаться с символа "#")
# - строка - название заголовка группы
# (строка должна начинаться с символа "!")
#
# Формат задания строки домена:
# - имя домена (обязательно первым)
# - значение истечения срока в днях (целое число)
# - значение интервала в секундах перед тем
# как перейти к следующей проверке (sleep:целое число)
# - стоимость продления домена (cost:float)
#
# Например:
# ! Группа 1
# имя_домена
# имя_домена число
#
# ! Группа 2
# имя_домена число sleep:число cost:float
# имя_домена sleep:число число 
# имя_домена sleep:число
#
# Если значение истечения срока в днях не задано,
# используется значение по-умолчанию или из параметра
# командной строки
#
# Если значение интервала в секундах перед тем как
# перейти к следующей проверке не задано,
# используется значение по-умолчанию или из параметра
# командной строки
#
# Если значение стоимости продления домена не задано,
# используется значение по-умолчанию или из параметра
# командной строки
#
#-------------------------------------------------------------

! Это пример заголовка группы
a.ru
linux.cafe 1000 sleep:8 cost:890.00
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
mikrotik.com
git-scm.com
github.com
python.org

! Социальные сети
livejournal.com
facebook.com
twitter.com

! Youtube
youtube.tv  
youtube.com
```

**-d STRING, --domain STRING**

Домен для проверки срока действия (по умолчанию Нет)

**-c, --print-to-console**

Включить печать в консоли (по умолчанию False)
В консоли печатаются столбцы "Domain Name", "Expiration Date" и "Days Left". 

**-l, --long-format**

Включить подробную печать в консоли (по умолчанию False)
В консоли печатаются столбцы "Domain Name", "Whois server", "Registrar", "Expiration Date" и "Days Left". 

**-i SECONDS, --interval-time SECONDS**

Время ожидания между whois-запросами (в секундах, по умолчанию 60)

**-x DAYS, --expire-days DAYS**

Порог истечения срока действия для проверки (в днях по умолчанию 60)
За сколько дней перед окончанием срока регистрации домена начинать предупреждать.

**-s FLOAT, --cost-per-domain FLOAT**

Стоимость продления домена (по умолчанию 0.00)


**-t, --use-telegram**

Отправить предупреждающее сообщение через Telegram (по умолчанию False)

**-p URL, --proxy URL**

Ссылка на прокси (только для Telegram), например: socks5://127.0.0.1:9150 (по умолчанию None). В России, Роскомнадзор предписывает всех провайдеров блокировать работу Telegram. О том, как преодолеть блокировку Telegram я рассказывать здесь не стану.

**-e EMAIL, --email-to EMAIL**

Отправить предупреждение на адрес электронной почты (по умолчанию Нет). Здесь необходимо указать email адрес получателя.

**-subject STRING, --email-subject STRING**

Добавить свой текст в тему email-письма (по умолчанию Нет). Это дополнительная опция для --email-to.

**-ssl, --email-ssl**

Отправить email-письмо по протоколу SSL (по умолчанию False). Это дополнительная опция для --email-to.

**-auth, --email-auth**

Отправлять email-письмо через SMTP с авторизацией (по умолчанию False). Это дополнительная опция для --email-to.

**-starttls, --email-starttls**

Отправить email-письмо по протоколу STARTTLS (по умолчанию False). Это дополнительная опция для --email-to.

**-oe, --use-only-external-whois**

Использовать только внешниюю утилиту whois (по умолчанию False). В этом режиме анализ данных внутренним движком не производится. Полностью доверяем работе внешней утилиты whois.

**-ee, --use-extra-external-whois**

Использовать внешниюю утилиту whois для дополнительного анализа (по умолчанию False)

Я рекомендую использовать этот режим. В этом режиме анализ данных сперва производится внутренним движком, а при возникновении ошибок - повторно уже внешней утилитой whois.
Почему я рекомендую именно этот режим?
Потому что в ряде случаев, например, для доменов из зоны .COM, управление доменами может быть делегировано каким-то другим региональным регистраторам. И если вы покупаете домен у регионального регистратора, то и продлевать домен вы будет у него, а не у родительского регистратора. Но так как синхронизация данных между региональным и родительским регистраторами происходит не моментально (задержка составлят от нескольких минут до нескольких часов), то если вы будете запрашивать whois информацию при помщи только внешней утилиты whois, вы получите данные от родительского регистратора. Внешняя утилита whois так работает. И если региональный регистратор к этому моменту ещё не успеет синхронизировать свои данные с родительским, вы получите ложное сообщение о том, что домен ещё не продлен, хотя на самом деле с ним уже все хорошо. Внутренний движок скрипта позволяет обнаруживать факт делегирования управления доменами от родительского регистратора к региональному. Информацию о сроке регистрации домена внутренний движок берет от регионального регистратора чьи данные являются наиболее достоверными и свежими.

**-nb, --no-banner**

Не печатать баннер (по умолчанию False).
Баннер, это информация о среде исполнения скрипта: версия Python, имя компьютера, имя ОС, релиз ОС, версия ОС, архитектура, ЦПУ, сводная таблица предустановленных опций и информация о пути к внешней утилите whois.

#### Внешняя утилита whois
В большинстве ОС Linux утилита whois уже имеется. Если нет, установите её.
Например:

Для Ubuntu/Debian:

```console
$ sudo apt update && sudo apt upgrade
$ sudo apt install whois
```

Для RHEL 6.x/RHEL 7.x/CentOS 6.x/CentOS 7.x:

```console
$ sudo yum install jwhois
```

Для RHEL 8.x/CentOS 8.x/Fedora 22 и выше:

```console
$ sudo dnf install jwhois
```

Для Arch/Manjaro:

```console
$ sudo pacman -S whois
```

Для Apple macOS:

```console
$ brew install whois
```


Для ОС Microsoft Windows лучше всего использовать форк **whois** из пакета **cygwin**. 

Загрузите и запустите [cygwin](https://www.cygwin.com/). В ходе установки **cygwin** задайте установку пакета **whois**. Запомните, куда устанавливается сам **cygwin** (например, в папку **c:\cygwin64**). 

После установки **cygwin** откройте командную строку с правами администратора.

Примечание: используйте **CMD.exe**, не используйте *Powershell* (для него команда совсем другая)! 

Выполните команду (*смотрите ниже*; в Windows 7/8/8.1/10 **переменные среды** можно изменять через графический интерфейс пользователя):

```console
> setx /M PATH "c:\cygwin64\bin;%PATH%"
```

Обратите внимание! Для полноценной работы утилиты **whois** из состава пакета **cygwin** требуются файлы:

    whois.exe
    cygiconv-2.dll
    cygidn-11.dll
    cygintl-8.dll
    cygwin1.dll

## Глобальные константы в скрипте
Часть опций находится внутри срипта. Нет никакого смысла выносить их в параметры, так как настроить их требуется всего один раз, после чего успешно о них забыть. 

### Параметры SMTP
**SMTP_SERVER**

адрес SMTP сервера

Примеры:

```python
    SMTP_SERVER = os.getenv("SMTP_SERVER", "localhost")
    # SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")    
```

**SMTP_PORT**

SMTP порт

Примеры:
    
```python
    # SMTP_PORT = int(os.getenv("SMTP_PORT", 587))  # Для starttls
    # SMTP_PORT = int(os.getenv("SMTP_PORT", 465))  # Для SSL
    SMTP_PORT = int(os.getenv("SMTP_PORT", 25))   # По умолчанию
```

**SMTP_SENDER**

Email адрес отправителя

Примеры:

```python
    SMTP_SENDER = os.getenv("SMTP_SENDER", "user@gmail.com")
```

**SMTP_PASSWORD**

SMTP пароль

Примеры:

```python
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "P@ssw0rd")
```

### Параметры Telegram
**TELEGRAM_TOKEN**

Токен Telegram бота

Примеры:

```python
    TELEGRAM_TOKEN = 'NNNNNNNNN:NNNSSSSaaaaaFFFFFEEE3gggggQQWFFFFF01z'
```

**TELEGRAM_CHAT_ID**

Идентификатор канала Telegram

Примеры :

```python
    TELEGRAM_CHAT_ID = '-NNNNNNNNN'
```

Получить помощь по API Telegram: 
[https://core.telegram.org/bots](https://core.telegram.org/bots)
Создать бота можно пообщавшись в Telegram с [**@BotFather**](https://telegram.me/BotFather)

**TELEGRAM_URL**

Telegram API URL

Примеры:

```python
    TELEGRAM_URL = "https://api.telegram.org/bot" + TELEGRAM_TOKEN + "/"
```

### Опции внешней утилиты whois
**WHOIS_COMMAND**

Команда запуска внешней утилиты whois

Примеры:

```python
    WHOIS_COMMAND = "whois"
    # WHOIS_COMMAND = "/usr/bin/whois"
    # WHOIS_COMMAND = "c:\\cygwin64\\bin\\whois.exe"
```

Примечание: Не используйте для ОС Microsoft Windows аналогичную утилиту whois от автора Марка Руссиновича.
При отправке whois-запросов на некотрые whois-сервера (например, на сервера GoDaddy.com) она может зависнуть или вернуть неверный результат.

**WHOIS_COMMAND_TIMEOUT**

Максимальное время ожидания выдачи результата от внешней утилиты whois (в секундах). По истечении этого времени внешний процесс whois будет принудительно завершен. Сам скрипт продолжит свою работу.

Примеры:

```python
    WHOIS_COMMAND_TIMEOUT = 10
```

### Стоимость продления домена
**G_CURRENCY_SYMBOL**

Задаёт символ национальной валюты
    
Примеры:

```python
    G_CURRENCY_SYMBOL = '₽'
```

### Параметры оценки времени до окончания сроков регисрации домена
**G_SOON_ADD**

Сколько дней должно остаться до окончания срока регистрации домена, когда об окончании срока можно судить, как "очень скоро", но ещё Валидно.
Эти дни прибавляются к параметру --expire-days (или к аналогичному значению в файле списков доменных имен)

Примеры:

```python
    G_SOON_ADD = 21
```

Если --expire-days (или аналогичное значение в файле списков доменных имен) равно 60 дней, то за 81 дня до окночания срока регистрации домена (60 + 21), такой домен будет в категории "Скоро". Эта опция влияет только на то, каким цветом будет напечатан домен в консоли. Никаких сообщений отправлено не будет.


## Как добавить скрипт в Linux cron
Для этого создайте **crontab** задачу, которая будет выполняться, например, каждую полночь от имени пользователя (создавать задачи от имени root не лучшая идея):

Предположим, ваш логин в Linux: **user**

Ваша домашняя папка: **/home/user**

Папка, где находится этот скрипт: **/home/user/py**

Чтобы запускать скрипт напрямую, выполните команду:
    
```console
$ chmod +x /home/user/py/ddec.py
```

Скорректируйте в первой строке скрипта [Шебанг (Unix)](https://ru.wikipedia.org/wiki/%D0%A8%D0%B5%D0%B1%D0%B0%D0%BD%D0%B3_(Unix)), например:

Показать путь, где расположен python:
    
```console
$ which python
```
или
```console
$ which python3
```
    
Коррекция пути python в Шебанг:

```python
#!/usr/bin/python
#!/usr/bin/python3
#!/usr/bin/env python
#!/usr/bin/env python3
```

Переименуйте скрипт:

```console
$ mv /home/user/py/ddec.py /home/user/py/ddec
```

Проверьте запуск скрипта:

```console
$ /home/user/py/ddec -h
$ /home/user/py/./ddec -h
```

Если всё нормально, запустите редактор **crontab**, если нет, вернитесь к настройке **Шебанг**:

```console
$ crontab -u user -e
```
Здесь **user** - это ваш логин в Linux


Если вы, как и я не любите vim (я не видел ни одного человека, в совершенстве владеющего этим редактором, хотя, наверное, он где-то есть), вы можете редактировать задачи в вашем любимом редакторе, например, так:

```console
$ EDITOR=nano crontab -u user -e
$ EDITOR=mcedit crontab -u user -e
```
или
```console
$ VISUAL=nano crontab -u user -e
$ VISUAL=mcedit crontab -u user -e
```

В файле задач создайте примерно такую запись (не используйте ключи **--print-to-console** и **--long-format**):

`0 0 * * * /home/user/py/ddec -nb -f /home/user/data/domains0.txt -i 5 -t -e user@gmail.com -ee >/dev/null 2>&1`

или

`0 0 * * * /home/user/py/./ddec -nb -f /home/user/data/domains0.txt -i 5 -t -e user@gmail.com -ee >/dev/null 2>&1`

Указывайте полные пути к файлу данных и скрипту.

Примечание: [cron](https://ru.wikipedia.org/wiki/Cron)

Посмотреть созданные задачи для пользователя **user** можно так:

```console
$ crontab -u user -l
```

Удалить все задачи пользователя **user** можно так:

```console
$ crontab -u user -r
```


## Как добавить скрипт в Планировщик заданий Microsoft Windows
Обратитесь за помощью к [документации](https://docs.microsoft.com/en-us/windows/desktop/taskschd/schtasks)

**Пример:**

`> schtasks /Create /SC DAILY /TN "Domain Expiration Checker" /TR "'с:\ddec.py' -nb -t -e my@email.com -ee -f 'c:\domains.txt'" /ST 23:59`

## Спасибо за идею
Автору оригинального скрипта: Matty < matty91 at gmail dot com > [https://github.com/Matty9191](https://github.com/Matty9191)

## Лицензия
[GNU General Public License v3.0](https://choosealicense.com/licenses/gpl-3.0/)

## Ограничения
Я, автор этого python-скрипта, написал этот скрипт исключительно для своих нужд. Никаких гарантий не предоставляется. Вы можете использовать этот скрипт свободно, без каких либо отчислений, в любых целях, кроме [Киберсквоттинга](https://ru.wikipedia.org/wiki/Киберсквоттинг).

Вы можете вносить любые правки в код скрипта и делать форк этого скрипта при условии указания ссылки на меня и на [Matty](https://github.com/Matty9191), как источника вашего вдохновения.

## Постскриптум
- Работа скрипта проверялась в Microsoft Windows 10, Linux Fedora 29/30/31/32/33, Linux Ubuntu Desktop 18.04/20.04/20.10, Linux CentOS 6/7/8, Linux Manjaro 18.0.2/20.2.
- Программный код скррипта не идеален. Но прошу простить меня за это. На момент написания этого скрипта, Python я изучаю всего две недели. Мне нравится этот язык программирования, он намного проще и вместе с тем мощнее, чем другие языки программирования, которыми я владею. 
- Все рекомендации данные мной для Apple macOS могут содержать в себе неточности. Простите, у меня нет под рукой Apple macBook (но вдруг, кто-то подарит мне его?).
- Да здравствует E = mc&sup2; !
- Желаю всем удачи!

## Последняя просьба
Пришло время положить конец Facebook. Работа там не является нейтральной с этической точки зрения: каждый день, когда вы идете туда на работу, вы делаете что-то не так. Если у вас есть учетная запись Facebook, удалите ее. Если ты работаешь в Facebook, увольняйся.

И давайте не будем забывать, что Агентство национальной безопасности должно быть уничтожено.

*(c) [David Fifield](mailto:david@bamsoftware.com)*

---

> Best regards, ak545 ( ru.mail&copy;ak545&sup2; )