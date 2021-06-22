#!/usr/bin/python3
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

import os
import threading
from multiprocessing.connection import Listener

import df_util
from df_util import df_logger


# global CONFIG
CONFIG = df_util.Config()


def execute_command(command, message):
    status = 500
    msg = 'command failed'
    if df_logger:
        df_logger.debug('execute: %s' % command)
    if CONFIG.SYS_DEBUG:
        if os.system('echo "exec: \'' + command + '\'"') == 0:
            status = 200
            msg = message
    else:
        if os.system(command) == 0:
            status = 200
            msg = message
    return [status, msg]


def control_interface(thread_name):
    global CONFIG
    listener = None

    while True:
        address = ('localhost', CONFIG.SYS_IPC_PORT)  # family is deduced to be 'AF_INET'
        try:
            listener = Listener(address, authkey=bytes(CONFIG.WEB_SECRET, 'utf-8'))
            conn = listener.accept()

            while True:
                if df_logger:
                    df_logger.debug('[%s] connection accepted from: %s' % (thread_name, listener.last_accepted))

                msg = conn.recv()
                # reboot system
                if msg == 'c:system:restart':
                    if df_logger:
                        df_logger.debug('[%s] restart message received: %s' % (thread_name, msg))
                    conn.send(execute_command(CONFIG.SYS_CMD_RESTART, 'restarting, please wait...'))
                    conn.close()
                    break

                # shutdown system
                if msg == 'c:system:shutdown':
                    if df_logger:
                        df_logger.debug('[%s] shutdown message received: %s' % (thread_name, msg))
                    conn.send(execute_command(CONFIG.SYS_CMD_SHUTDOWN, 'powering off, please wait...'))
                    conn.close()
                    break

                # close connection
                elif msg == 'close':
                    conn.send(200)
                    conn.close()
                    break

        except Exception as ex_srv:
            if df_logger:
                df_logger.info('[%s] server error: %s' % (thread_name, str(ex_srv)))

        finally:
            if listener is not None:
                listener.close()
                listener = None


if __name__ == "__main__":
    # init logging
    df_util.init_logger(CONFIG)

    if CONFIG.SYS_DEBUG:
        if df_logger:
            df_logger.info('Debug mode, commands will be logged but not executed!')

    try:
        # start ipc thread
        ipc = threading.Thread(target=control_interface, args=('ipc',))
        ipc.start()

        # start IPC server
        ipc.join()

    except KeyboardInterrupt:
        if df_logger:
            df_logger.critical('Stopping user aborted with CTRL+C')

    except Exception as ex:
        if df_logger:
            df_logger.critical('Fatal error: %s', ex)

    finally:
        pass
