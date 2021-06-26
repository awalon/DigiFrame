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

'''
Settings Template and Meta Information
'''
SETTINGS = {
    "global": {
        "_section": {
            "name": "General"
        },
        "system_name": {
            "name": "System name",
            "info": "Name/Title of this instance",
            "value": "DigiFrame"
        },
        "time_format": {
            "name": "Timestamp format",
            "info": "Format of Date and Time used for Timestamps",
            "value": "%m/%d/%Y, %H:%M:%S",
            "options": ["%m/%d/%Y, %H:%M:%S",
                        "%A %d. %B %Y, %H:%M:%S"]
        },
        "time_zone": {
            "name": "Timezone",
            "type": "str",
            "value": "Europe/Berlin"
        }
    },
    "logger": {
        "_section": {
            "name": "Logger"
        },
        "use_syslog": {
            "name": "Use syslog",
            "info": "Enable syslog output for log messages",
            "value": True
        },
        "log_level": {
            "name": "Log level",
            "info": "Define log level to control amount of log messages",
            "value": "INFO",
            "options_select": ["DEBUG", "INFO", "WARNING", "ERROR", "FATAL"]
        }
    },
    "slideshow": {
        "_section": {
            "name": "Slideshow"
        },
        "debug": {
            "name": "Debug mode",
            "info": "Debug mode, if enabled service stays active even on missing fim.",
            "value": False
        },
        "ipc_port": {
            "name": "IPC port",
            "info": "Local port for inter process communication (IPC), which is used by web server process.",
            "value": 6000
        },
        "picture_timeout": {
            "name": "Picture timeout",
            "info": "Number of seconds a picture is displayed.",
            "value": 15
        },
        "picture_path": {
            "name": "Picture path",
            "info": "Path to pictures used for slideshow.",
            "value": "/home/digiframe/pictures"
        }
    },
    "gpio": {
        "_section": {
            "name": "GPIO",
            "enabled": False
        },
        "pir_pin": {
            "name": "PIN number",
            "info": "That’s the GPIO pin on which the PIR is plugged on",
            "value": 16
        },
        "motion_timeout": {
            "name": "Motion timeout",
            "info": "Number of seconds to wait after last motion detection before stopping the slideshow.",
            "value": 600
        }
    },
    "sync": {
        "_section": {
            "name": "Synchronization"
        },
        "mode": {
            "name": "Mode",
            "info": "Controls synchronization mode: [none|rclone|rsync]",
            "value": "none",
            "options_select": ["none", "rclone", "rsync"],
        },
        "source": {
            "name": "Source",
            "info": "Path of source used for synchronization. \n"
                    "rclone source like '<rclone remote>:<remote path>' or \n"
                    "rsync source like '<remote_user>@<remote_host>:<remote path>' "
                    "(ssh private key '~/.ssh/rsync-key')",
            "value": "rcl:Digiframe/"
        },
        "interval": {
            "name": "Interval",
            "info": "Time between syncs",
            "value": 3600
        }
    },
    "system": {
        "_section": {
            "name": "System",
            "info": "Configuration of system service, which provides system integration."
        },
        "debug": {
            "name": "Debug mode",
            "info": "Debug mode, if enabled reboot and shutdown commands are disabled.",
            "value": False
        },
        "ipc_port": {
            "name": "IPC port",
            "info": "Local port for inter process communication (IPC), which is used by web server process.",
            "value": 6002
        },
        "cmd_restart": {
            "name": "Restart command",
            "info": "Command used for system restart",
            "value": "sudo reboot"
        },
        "cmd_shutdown": {
            "name": "Shutdown command",
            "info": "Command used for system shutdown",
            "value": "sudo poweroff"
        }
    },
    "web": {
        "_section": {
            "name": "Webserver"
        },
        "debug": {
            "name": "Debug mode",
            "info": "Additional log messages and default values for IPC commands (if service is not available)",
            "value": False
        },
        "secret": {
            "name": "Secret",
            "info": "Secret to restrict IPC communication.",
            "value": None
        },
        "host": {
            "name": "Host",
            "info": "IP used by webserver process",
            "value": "0.0.0.0"
        },
        "port": {
            "name": "Port",
            "info": "Port used by webserver process",
            "value": 80
        },
        "ssl": {
            "enabled": False,
            "name": "SSL Mode",
            "info": "Use SSL mode",
            "value": False
        },
        "cert": {
            "enabled": False,
            "name": "SSL Certificate",
            "info": "SSL Certificate file",
            "value": "/etc/digiframe/ssl/digiframe-web.crt"
        },
        "key": {
            "enabled": False,
            "name": "SSL key",
            "info": "SSL Key file for certificate",
            "value": "/etc/digiframe/ssl/digiframe-web.key"
        },
        "logo": {
            "name": "System logo",
            "value": "logo.svg"
        },
        "theme_color": {
            "name": "Color",
            "info": "Highlight color",
            "type": "color",
            "value": "#ab1a1a"
        },
        "static_path": {
            "name": "Static path",
            "info": "Path with static files provided by webserver",
            "value": "static"
        },
        "templates_path": {
            "name": "Template path",
            "info": "Path with page templates used by webserver",
            "value": "templates"
        },
        "thumbnail_cache_enabled": {
            "name": "Cache enabled",
            "info": "Cache thumbnails of slideshow pictures",
            "value": True
        },
        "thumbnail_cache": {
            "name": "Cache path",
            "info": "Path used for thumbnail cache",
            "value": "/home/digiframe/cache/"
        },
        "user": {
            "1": {
                "active": True,
                "name": "admin",
                "email": "admin@digiframe",
                "description": "Admin",
                "password": "x||passw0rd"
            }
        }
    }
}
