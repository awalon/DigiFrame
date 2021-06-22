"""
        DigiFrame is a lightweight solution for digital picture frame.
        Copyright (C) 2021 Awalon

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import base64
import getpass
import json
import logging.handlers
import io
import threading
import os
import sys
import psutil
import stat
import hashlib
import time
import pytz
from datetime import timezone


# Global logging instance
df_logger = logging.getLogger('digiframe')

# global file with defaults first, as values are read and overwritten as defined here
proc_user_name = getpass.getuser()
script_path = os.path.dirname(os.path.realpath(__file__))
config_files = ['/etc/digiframe/digiframe.json',
                '/etc/digiframe/digiframe-%s.json' % proc_user_name,
                '/home/%s/.config/digiframe/digiframe.json' % proc_user_name,
                '/home/digiframe/.config/digiframe/digiframe.json',
                os.path.join(script_path, '/etc/digiframe.json'),
                os.path.join(script_path, '/etc/digiframe-%s.json' % proc_user_name)
                ]

# add debug/test files
config_files += [
    os.path.join(script_path, '../../home/%s/.config/digiframe/digiframe.json' % proc_user_name),
    os.path.join(script_path, '../../home/digiframe/.config/digiframe/digiframe.json'),
    os.path.join(script_path, '../../home/digiframe/.config/digiframe/digiframe-%s.json' % proc_user_name)
    ]


class Config:
    import string
    import random
    from df_settings import SETTINGS

    # config = None
    files = None

    GLOBAL_SYS_NAME = 'Digiframe'
    GLOBAL_TIME_FORMAT = '%m/%d/%Y, %H:%M:%S'
    GLOBAL_TIME_ZONE = 'Europe/Berlin'

    LOG_LEVEL = logging.INFO  # Define log level
    LOG_TO_SYSLOG = True  # Enable syslog output

    DEBUG = False
    IPC_PORT = 6000
    PICTURE_TIMEOUT = 15  # number of seconds a picture is displayed
    PICTURE_PATH = '/home/digiframe/pictures/'  # path to pictures used for slideshow
    GPIO_PIR_PIN = 16  # That’s the GPIO pin on which the PIR is plugged on
    GPIO_NO_MOTION_TIMEOUT = 600  # number of seconds to wait after last motion detection before stopping the slideshow

    SYNC_MODE_NONE = None
    SYNC_MODE_RCLONE = 'rclone'
    SYNC_MODE_RSYNC = 'rsync'
    SYNC_MODE = SYNC_MODE_RCLONE  # sync mode [none|rclone|rsync]
    SYNC_SOURCE = 'rcl:Digiframe/'  # sync source path (ex.: rclone pattern)
    SYNC_INTERVAL = 3600  # time between syncs

    SYS_DEBUG = False
    SYS_IPC_PORT = 6001
    SYS_CMD_RESTART = 'reboot'
    SYS_CMD_SHUTDOWN = 'poweroff'

    WEB_DEBUG = False
    WEB_SECRET_DEFAULT = ''.join(random.choices(
                                         string.ascii_uppercase + string.ascii_lowercase + string.digits,
                                         k=20))  # private key for IPC and Web Control
    WEB_SECRET = WEB_SECRET_DEFAULT
    WEB_HOST = '0.0.0.0'
    WEB_PORT = 80
    WEB_SSL = False
    WEB_SSL_CERT = '/etc/digiframe/ssl/digiframe-web.crt'
    WEB_SSL_KEY = '/etc/digiframe/ssl/digiframe-web.key'
    WEB_LOGO = 'logo.svg'
    WEB_THEME_COLOR = 'ab1a1a'
    WEB_STATIC_PATH = 'static'
    WEB_TEMPLATES_PATH = 'templates'
    WEB_THUMBNAIL_CACHE = False
    WEB_THUMBNAIL_CACHE_PATH = '/home/digiframe/cache/'

    def __init__(self):
        self.reload()

    def __import_settings(self, settings):
        # overwrite master with settings from current file
        for section in settings:
            if section in self.SETTINGS:
                config_section = self.SETTINGS[section]
                for option in settings[section]:

                    # skip meta options starting with "_"
                    if option[0] != "_":
                        if option in config_section:
                            config_option = config_section[option]

                            # handle regular values
                            if 'value' in config_option:
                                if df_logger:
                                    df_logger.debug("[%s] %s: %s -> %s" %
                                                    (section, option,
                                                     str(config_option['value']),
                                                     str(settings[section][option]['value'])))
                                config_option['value'] = settings[section][option]['value']

                            # handle user definitions
                            elif 'user' == option:
                                if len(settings[section][option].keys()) > 0:
                                    config_section[option] = config_option = dict()
                                for user in settings[section][option]:
                                    if df_logger:
                                        df_logger.debug("[%s] %s: %s" %
                                                        (section, option,
                                                         str(settings[section][option][user])))
                                    config_option[user] = settings[section][option][user]

                            else:
                                if df_logger:
                                    df_logger.error('Unknown/missing value of "%s" in section "%s" was ignored.' %
                                                    (option, section))

                        else:
                            if df_logger:
                                df_logger.error('Unknown option "%s" in section "%s" was ignored.' % (option, section))

            else:
                if df_logger:
                    df_logger.error('Unknown section "%s" was ignored.' % section)

    def __read_config(self):
        self.files = []
        for file in config_files:
            try:
                fh = open(file=file, encoding='utf-8')
                config_json = json.load(fh)
                fh.close()

                self.__import_settings(config_json)
                self.files.append(file)

            except Exception as open_error:
                if df_logger:
                    df_logger.info('Can not read config from "%s": %s' % (file, open_error.__str__()))

        if df_logger:
            df_logger.info('use config from: ' + ', '.join(self.files))
        return len(self.files)

    def __write_config(self, config_data):
        if len(self.files) == 0:
            file = config_files[0]
        else:
            file = self.files[-1]
        try:
            fh = open(file=file, encoding='utf-8', mode='w')
            json.dump(obj=config_data, fp=fh, indent=4)
            fh.close()

            if df_logger:
                df_logger.debug('Config written to: %s' % file)
            return file

        except Exception as open_error:
            if df_logger:
                df_logger.error('Can not write config to "%s": %s' % (file, open_error.__str__()))

        return None

    def get_setting(self, section: str, option: str, default=None):
        if type(self.SETTINGS) is dict:
            if section in self.SETTINGS:
                section = self.SETTINGS.get(section)
                if type(section) is dict:
                    if option in section:
                        option = section.get(option)
                        if 'value' in option:
                            value = option.get('value')
                            if 'type' not in option:
                                # get value based on type of default value
                                option['type'] = type(value).__name__
                        return option
                    else:
                        return None
                else:
                    return None
        else:
            return None
        return default

    def get_option(self, section: str, option: str, default=None):
        option = self.get_setting(section=section, option=option, default=default)
        if type(option) is dict:
            if 'value' in option:
                if not option.get('value') is None:
                    return option.get('value')
                else:
                    return default
        else:
            return option
        return default

    def set_option(self, section: str, option: str, value):
        if option[0] != '_' and not (section == 'web' and option == 'user'):
            # skip invalid and non existing sections
            if section in self.SETTINGS:

                current_section = self.SETTINGS[section]
                section_enabled = True
                if '_section' in current_section and 'enabled' in current_section['_section']:
                    section_enabled = current_section['_section']['enabled']

                # skip disabled sections
                if section_enabled:
                    setting = self.get_setting(section=section, option=option, default=None)

                    # skip disabled and non existing options
                    if setting is not None:
                        option_enabled = True
                        if 'enabled' in setting:
                            option_enabled = setting['enabled']

                        # skip disabled options
                        if option_enabled:
                            if 'value' in setting:
                                if 'type' in setting:
                                    if setting['type'] == 'bool':
                                        if value in ['1', 1, 'true', True, 'on', 'yes', 'enabled', 'active']:
                                            value = True
                                        else:
                                            value = False
                                    elif setting['type'] == 'int':
                                        if value is None or value == '':
                                            value = 0
                                        else:
                                            value = int(value)
                                self.SETTINGS[section][option]['value'] = value
                                return value
        if self.WEB_DEBUG:
            df_logger.debug('Invalid/Disabled setting [%s] %s: %s' % (section, option, value))
        return None

    def reload(self):
        files = self.__read_config()
        if files == 0:
            df_logger.warning('+++ Config file not found, using default settings!')

        # ## global ##
        # system name
        self.GLOBAL_SYS_NAME = self.get_option('global', 'system_name', self.GLOBAL_SYS_NAME)
        # time format
        self.GLOBAL_TIME_FORMAT = self.get_option('global', 'time_format', self.GLOBAL_TIME_FORMAT)
        # time zone
        self.GLOBAL_TIME_ZONE = self.get_option('global', 'time_zone', self.GLOBAL_TIME_ZONE)

        # ## Logger ##
        # Define log level
        log_level = self.get_option('logger', 'log_level', logging.getLevelName(self.LOG_LEVEL))
        if logging.getLevelName(logging.WARNING) == log_level:
            self.LOG_LEVEL = logging.WARNING
        elif logging.getLevelName(logging.DEBUG) == log_level:
            self.LOG_LEVEL = logging.DEBUG
        elif logging.getLevelName(logging.ERROR) == log_level:
            self.LOG_LEVEL = logging.ERROR
        elif logging.getLevelName(logging.FATAL) == log_level:
            self.LOG_LEVEL = logging.FATAL
        else:
            self.LOG_LEVEL = logging.INFO
        # Enable syslog output
        self.LOG_TO_SYSLOG = self.get_option('logger', 'use_syslog', self.LOG_TO_SYSLOG)

        self.DEBUG = self.get_option('slideshow', 'debug', self.DEBUG)
        # local port for inter process communication
        self.IPC_PORT = self.get_option('slideshow', 'ipc_port', self.IPC_PORT)
        # number of seconds a picture is displayed
        self.PICTURE_TIMEOUT = self.get_option('slideshow', 'picture_timeout', self.PICTURE_TIMEOUT)
        # path to pictures used for slideshow
        self.PICTURE_PATH = self.get_option('slideshow', 'picture_path', self.PICTURE_PATH)

        # ## GPIO motion detection ##
        # That’s the GPIO pin on which the PIR is plugged on
        self.GPIO_PIR_PIN = self.get_option('gpio', 'pir_pin', self.GPIO_PIR_PIN)
        # number of seconds to wait after last motion detection before stopping the slideshow
        self.GPIO_NO_MOTION_TIMEOUT = self.get_option('gpio', 'motion_timeout', self.GPIO_NO_MOTION_TIMEOUT)

        # sync mode [none|rclone]
        self.SYNC_MODE = self.get_option('sync', 'mode', self.SYNC_MODE)
        # sync source path
        self.SYNC_SOURCE = self.get_option('sync', 'source', self.SYNC_SOURCE)
        # time between syncs
        self.SYNC_INTERVAL = self.get_option('sync', 'interval', self.SYNC_INTERVAL)

        # ## system interface ##
        # debug
        self.SYS_DEBUG = self.get_option('system', 'debug', self.SYS_DEBUG)
        # local port for inter process communication
        self.SYS_IPC_PORT = self.get_option('system', 'ipc_port', self.SYS_IPC_PORT)
        # system restart command
        self.SYS_CMD_RESTART = self.get_option('system', 'cmd_restart', self.SYS_CMD_RESTART)
        # system shutdown command
        self.SYS_CMD_SHUTDOWN = self.get_option('system', 'cmd_shutdown', self.SYS_CMD_SHUTDOWN)

        # ## webserver ##
        # debug
        self.WEB_DEBUG = self.get_option('web', 'debug', self.WEB_DEBUG)
        # private key for IPC and Web Control
        self.WEB_SECRET = self.get_option('web', 'secret', self.WEB_SECRET)
        # listen address / host
        self.WEB_HOST = self.get_option('web', 'host', self.WEB_HOST)
        # listen port
        self.WEB_PORT = self.get_option('web', 'port', self.WEB_PORT)
        # enable SSL
        self.WEB_SSL = self.get_option('web', 'ssl', self.WEB_SSL)
        # SSL certificate file
        self.WEB_SSL_CERT = self.get_option('web', 'cert', self.WEB_SSL_CERT)
        # SSL key file
        self.WEB_SSL_KEY = self.get_option('web', 'key', self.WEB_SSL_KEY)
        # Logo
        self.WEB_LOGO = self.get_option('web', 'logo', self.WEB_LOGO)
        # Theme Color
        self.WEB_THEME_COLOR = self.get_option('web', 'theme_color', self.WEB_THEME_COLOR)
        # Static path
        self.WEB_STATIC_PATH = self.get_option('web', 'static_path', self.WEB_STATIC_PATH)
        # Template path
        self.WEB_TEMPLATES_PATH = self.get_option('web', 'templates_path', self.WEB_TEMPLATES_PATH)
        # Thumbnail cache
        self.WEB_THUMBNAIL_CACHE = self.get_option('web', 'thumbnail_cache_enabled', self.WEB_THUMBNAIL_CACHE)
        # Thumbnail cache path
        self.WEB_THUMBNAIL_CACHE_PATH = self.get_option('web', 'thumbnail_cache', self.WEB_THUMBNAIL_CACHE_PATH)

        if self.WEB_SECRET_DEFAULT == self.WEB_SECRET:
            # write new secret to file for other services
            df_logger.error("New secret was generated, please restart core services")
            self.set_option('web', 'secret', self.WEB_SECRET)
            self.save()

        return files

    def save(self):
        """
        extract values from SETTINGS object and write it to file
        """
        json_conf = dict()
        for section in self.SETTINGS:
            current_section = self.SETTINGS[section]
            section_enabled = True
            if '_section' in current_section and 'enabled' in current_section['_section']:
                section_enabled = current_section['_section']['enabled']

            # skip disabled sections
            if section_enabled:
                for option in current_section:
                    # skip meta data for section
                    if option[0] != '_':
                        setting = self.get_setting(section=section, option=option, default=None)

                        # skip disabled and non existing options
                        if setting is not None:
                            option_enabled = True
                            if 'enabled' in setting:
                                option_enabled = setting['enabled']

                            # skip disabled options
                            if option_enabled:
                                if section not in json_conf:
                                    json_conf[section] = dict()

                                if 'value' in setting:
                                    value = {"value": setting['value']}
                                else:
                                    value = setting
                                json_conf[section][option] = value

        df_logger.debug("New config: %s" % json_conf)
        file = self.__write_config(json_conf)
        if file:
            df_logger.info("Configuration saved to: %s" % file)
            return True
        return False

    def time_zone(self):
        if self.GLOBAL_TIME_ZONE:
            return pytz.timezone(self.GLOBAL_TIME_ZONE)
        return timezone.utc


class ConfigUser:
    # password
    import hashlib
    import hmac

    config = None

    def __init__(self, config: Config):
        self.config = config

    def get_users(self):
        user_list = {}
        users = self.config.get_setting('web', 'user', dict())
        for uid, user in users.items():
            user_list[uid] = self.get_user(user['name'])
        return user_list

    def __load_user(self, uid: str, user: dict) -> dict:
        if 'id' not in user:
            user['id'] = uid

        if 'active' not in user:
            user['active'] = True
        else:
            if str(user['active']).lower() in ['1', 1, 'true', True, 'on', 'yes', 'enabled', 'active']:
                user['active'] = True
            else:
                user['active'] = False
        if 'name' not in user:
            user['name'] = uid
        else:
            user['name'] = user['name'].lower()
        if 'email' not in user:
            user['email'] = user['name'] + '@localhost'
        if 'description' not in user:
            user['description'] = user['name']

        if 'password' not in user:
            user['password'] = 'x'
        if user['password'] is None or user['password'] == 'x' or user['password'] == '########':
            # no password defined, user will be disabled
            user['active'] = False
            user['password'] = None
        elif len(user['password']) > 3 and user['password'][0:3] == 'x||':
            user['password'] = self.hash_new_password(user['password'][3:])
        return user

    def get_user_by_id(self, user_id: str):
        users = self.config.get_setting('web', 'user', dict())
        uid = user_id.strip().lower()
        if uid in users:
            return self.__load_user(uid, users.get(uid))
        return None

    def get_user(self, user_name: str):
        users = self.config.get_setting('web', 'user', dict())
        user_name = str(user_name).strip().lower()
        for uid, user in users.items():
            if user_name == user['name'].lower():
                return self.__load_user(uid, user)
        return None

    def __max_id(self) -> int:
        users = self.config.get_setting('web', 'user', dict())
        max_id = 0
        for uid in users:
            if int(uid) > max_id:
                max_id = int(uid)
        return max_id

    def append_user(self, user: dict):
        users = self.config.get_setting('web', 'user', dict())
        uid = self.__max_id() + 1
        if len(user['name'].strip()) == 0:
            return False, 'User with temporary ID "%s" was not added, user name missing!' % (user['id']), 'danger'
        user['id'] = uid
        new_user = self.__load_user(str(uid), user)
        users[str(uid)] = new_user
        if user['active'] is False and user['password'] in ['x', '########', None]:
            return True, 'User "%s" with ID %s was added but disabled, please check password!' \
                   % (user['name'], uid), 'warning'
        return True, 'User "%s" was successfully added with ID %s!' % (user['name'], uid), 'info'

    def remove_user_by_id(self, user_id: str):
        users = self.config.get_setting('web', 'user', dict())
        if user_id in users:
            del users[user_id]
            self.config.save()
            return True
        return False

    def hash_new_password(self, password: str) -> str:
        """
        Hash the provided password with a randomly-generated salt and return the
        salt and hash to store in the database.
        """
        salt = os.urandom(16)
        pw_hash = self.hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        salted_pw_hash = salt + pw_hash
        pw_secret = base64.b64encode(salted_pw_hash)
        return pw_secret.decode(encoding='utf-8')

    def is_correct_password(self, pw_secret: str, password: str) -> bool:
        """
        Given a previously-stored salt and hash, and a password provided by a user
        trying to log in, check whether the password is correct.
        """
        salted_pw_hash = base64.b64decode(pw_secret.encode())
        salt = salted_pw_hash[0:16]
        pw_hash = salted_pw_hash[16:]
        return self.hmac.compare_digest(
            pw_hash,
            self.hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        )


def init_logger(df_config: Config):
    from logging import config
    global df_logger

    # init logging (redirects, syslog)
    LOGGING = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'verbose': {
                'format': '%(name)s[%(process)d]: %(levelname)s - %(message)s'
            },
        },
        'handlers': {
            'stdout': {
                'class': 'logging.StreamHandler',
                'stream': sys.stdout,
                'formatter': 'verbose',
            },
            'sys-logger6': {
                'class': 'logging.handlers.SysLogHandler',
                'address': '/dev/log',
                'facility': "local6",
                'formatter': 'verbose',
            },
        },
        'loggers': {
            'digiframe': {
                'handlers': ['stdout'],
                'level': df_config.LOG_LEVEL,
                'propagate': True,
            },
        }
    }

    if df_config.LOG_TO_SYSLOG:
        if psutil.Process(os.getpid()).ppid() == 1:
            LOGGING['formatters']['verbose']['format'] = '%(levelname)s - %(message)s'
        else:
            # Not called by systemd
            # noinspection PyTypeChecker
            LOGGING['loggers']['digiframe']['handlers'] = ['sys-logger6', 'stdout']

    config.dictConfig(LOGGING)
    df_logger = logging.getLogger('digiframe')

    sys.stdout = StreamToLogger(df_logger, logging.DEBUG)
    sys.stderr = StreamToLogger(df_logger, logging.ERROR)

    df_logger.info('DigiFrame  Copyright (C) 2021  Awalon')
    df_logger.info('This program comes with ABSOLUTELY NO WARRANTY.')
    df_logger.info('This is free software, and you are welcome to redistribute it')
    df_logger.info('under certain conditions.')

    return df_logger


def get_file_list(path: str, web_mode=False, child=False):
    if not os.path.exists(path):
        return []

    files_sorted_by_path = []
    file_paths = [os.path.join(path, file) for file in os.listdir(path)]
    file_statuses = [(os.stat(file_path), file_path) for file_path in file_paths]
    files = ((file_path, status[stat.ST_MTIME], status[stat.ST_MODE]) for status, file_path in file_statuses)
    # ... if stat.S_ISREG(status[stat.ST_MODE]))
    has_files = False
    for filepath, modification_time, mode in sorted(files):
        modification_date = time.ctime(modification_time)
        if stat.S_ISDIR(mode):  # directory
            (children, with_files) = get_file_list(filepath, web_mode=web_mode, child=True)
            if web_mode:
                files_sorted_by_path.append((filepath, 'd', modification_time, with_files))
            files_sorted_by_path += children
        elif stat.S_ISREG(mode) or stat.S_ISLNK(mode):  # file
            has_files = True
            filename = filepath  # os.path.basename(filepath)
            if web_mode:
                files_sorted_by_path.append((filename, 'f', modification_time, False))
            else:
                files_sorted_by_path.append(modification_date + " " + filename)
    if child:
        return files_sorted_by_path, has_files
    if web_mode:
        return [(path, 'd', os.stat(path)[stat.ST_MTIME], has_files)] + files_sorted_by_path
    return files_sorted_by_path


def get_file_list_hash(path):  # detect changes after sync
    files_sorted_by_date = get_file_list(path)
    file_list = ''.join(files_sorted_by_date)
    md5 = hashlib.md5()
    md5.update(file_list.encode())
    hash_key = md5.hexdigest() + ';c=' + str(len(files_sorted_by_date))
    if df_logger:
        df_logger.debug('source hash: %s' % hash_key)
    return hash_key, len(files_sorted_by_date)


def get_sys_uptime():
    try:
        try:
            return time.time() - psutil.boot_time()
        except Exception as ex_boot:
            if df_logger:
                df_logger.error('Error can not get boot time: %s' % ex_boot)
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.readline().split()[0])
    except Exception as ex_uptime:
        if df_logger:
            df_logger.error('Error can not get uptime: %s' % ex_uptime)
        uptime_seconds = -1
    return uptime_seconds


def get_sys_load():
    try:
        return psutil.getloadavg()
    except Exception as ex_ps_load:
        if df_logger:
            df_logger.error('Error can not get load (psutil): %s' % ex_ps_load)
        return os.getloadavg()


def get_sys_disk_usage(mount_point):
    disks = []
    if mount_point:
        disks.append((mount_point, psutil.disk_usage(mount_point)))
    else:
        for disk in psutil.disk_partitions():
            disks.append((disk.mountpoint, psutil.disk_usage(disk.mountpoint)))
    return disks


def get_ip_family_name(family):
    from socket import AF_INET, AF_INET6, AF_PACKET
    if family == AF_INET:
        return 'IPv4'
    elif family == AF_INET6:
        return 'IPv6'
    elif family == AF_PACKET:
        return 'MAC'
    else:
        return 'other'


def get_sys_cores():
    return psutil.cpu_count()


def get_sys_stat():
    net_ifs = psutil.net_if_addrs()
    return {
        'cpu_count': get_sys_cores(),
        'cpu_percent': psutil.cpu_percent(),
        'cpu_freq': psutil.cpu_freq(),
        'sys_load': get_sys_load(),
        'mem_virt': psutil.virtual_memory(),
        'mem_swap': psutil.swap_memory(),
        'net_if': net_ifs,
        '_net_if': [(net_if,
                    [({'address': net_info.address, 'family': get_ip_family_name(net_info.family), 'info': net_info})
                     for net_info in net_ifs[net_if]])
                    for net_if in net_ifs],
    }


class LogPipe(threading.Thread, io.BytesIO):

    def __init__(self, logger, level):
        """Setup the object with a logger and a loglevel
        and start the thread
        """
        threading.Thread.__init__(self)
        self.daemon = False
        self.logger = logger
        self.level = level
        self.fdRead, self.fdWrite = os.pipe()
        self.pipeReader = os.fdopen(self.fdRead)
        self.start()

    def fileno(self):
        """Return the write file descriptor of the pipe
        """
        return self.fdWrite

    def run(self):
        """Run the thread, logging everything.
        """
        for line in iter(self.pipeReader.readline, ''):
            self.logger.log(self.level, line.strip('\n'))

        self.pipeReader.close()

    def close(self):
        """Close the write end of the pipe.
        """
        os.close(self.fdWrite)


class StreamToLogger(io.BytesIO):
    """
    Fake file-like stream object that redirects writes to a logger instance.
    """

    def __init__(self, logger, level):
        super().__init__()
        self.logger = logger
        self.level = level
        self.linebuf = ''

    def write(self, buf):
        for line in buf.rstrip().splitlines():
            self.logger.log(self.level, line.rstrip())

    def flush(self):
        pass
