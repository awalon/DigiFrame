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

import df_util
from df_util import df_logger
import datetime
import logging.handlers
import sys
import time
import psutil
import subprocess
import threading
from multiprocessing.connection import Listener
# from RPi import GPIO


RESTART = False
TIME_REMIX = -1
TIME_RESYNC = -1
stop_control_interface = False
# config
# global CONFIG
CONFIG = df_util.Config()


def turn_off_cursor():
    try:
        terminal = open("/dev/tty1", "wb")
        subprocess.run(["setterm", "-cursor", "off"],
                       stdout=terminal, stderr=log_pipe_err,
                       env={"TERM": "xterm-256color"})
    except Exception as ex_cursor:
        if df_logger:
            df_logger.error('Can not disable cursor: %s' % ex_cursor)


def start_slideshow(splashshow):
    if splashshow:
        stop_splashshow(splashshow)
    try:
        cmd = ["fim", "--device", "/dev/fb0", "--vt", "1", "--no-commandline", "--quiet",
               "--recursive", CONFIG.PICTURE_PATH, "--execute-commands-early", '_scale_style="h"', "--execute-commands",
               'while(1){display;sleep "' + str(CONFIG.PICTURE_TIMEOUT) + '";next;}']
        if CONFIG.RANDOM:
            cmd.append("--random")
        slideshow = subprocess.Popen(cmd, stdout=log_pipe_out, stderr=log_pipe_err)
        time.sleep(5)  # Give time for fim to start so when the screen is turned on there’s already a picture displayed
        subprocess.run(["vcgencmd", "display_power", "1"], stdout=log_pipe_out, stderr=log_pipe_err)
        return slideshow
    except Exception as ex_slideshow:
        df_logger.error('Can not start slideshow: %s' % ex_slideshow)
        if CONFIG.DEBUG:
            splashshow = subprocess.Popen(['true'], stdout=log_pipe_out, stderr=log_pipe_err)
            time.sleep(5)
            return splashshow
    return None


def restart_slideshow(slideshow):
    if slideshow is not None and slideshow.poll() is None:
        slideshow.terminate()
    return start_slideshow(None)


def stop_slideshow(slideshow):
    try:
        subprocess.run(["vcgencmd", "display_power", "0"])
    except Exception as ex_power:
        df_logger.error('Can not disable display power: %s' % ex_power)
    if slideshow is not None and slideshow.poll() is None:
        slideshow.terminate()
    time.sleep(12)  # My screen waits 10 seconds before switching to sleep mode


def get_time():
    return datetime.datetime.now(tz=CONFIG.time_zone()).timestamp()


def sync_src():
    if CONFIG.SYNC_MODE == CONFIG.SYNC_MODE_RCLONE:
        df_logger.info('sync with rclone "'
                       + CONFIG.SYNC_SOURCE + '" to "' + CONFIG.PICTURE_PATH + '" (interval: '
                       + str(CONFIG.SYNC_INTERVAL) + ' sec)...')
        try:
            subprocess.run(["/usr/bin/rclone", "sync", CONFIG.SYNC_SOURCE, CONFIG.PICTURE_PATH],
                           stdout=log_pipe_out, stderr=log_pipe_err)
        except Exception as ex_sync:
            df_logger.error('Can not sync with rclone src: %s' % ex_sync)

    elif CONFIG.SYNC_MODE == CONFIG.SYNC_MODE_RSYNC:
        df_logger.info('sync with rsync "'
                       + CONFIG.SYNC_SOURCE + '" to "' + CONFIG.PICTURE_PATH + '" (interval: '
                       + str(CONFIG.SYNC_INTERVAL) + ' sec)...')
        try:
            subprocess.run(["/usr/bin/rsync", "-aP", "--no-owner", "--delete",
                            "-e ssh -i ~/.ssh/rsync-key -o PubkeyAuthentication=yes",
                            CONFIG.SYNC_SOURCE, CONFIG.PICTURE_PATH],
                           stdout=log_pipe_out, stderr=log_pipe_err)
        except Exception as ex_sync:
            df_logger.error('Can not sync with rsync src: %s' % ex_sync)

    else:  # CONFIG.SYNC_MODE_NONE
        df_logger.info('sync is disabled (None)...')

    file_hash, file_count = df_util.get_file_list_hash(CONFIG.PICTURE_PATH)
    return file_hash, file_count, get_time()


def start_splashshow():
    df_logger.info('splash screen...')
    turn_off_cursor()
    # kill old processes
    for proc in psutil.process_iter():
        try:
            if proc.name() == 'fim':
                df_logger.info('killing: ' + proc.name() + '[' + str(proc.pid) + ']')
                proc.kill()
        except psutil.NoSuchProcess:
            pass
        except psutil.AccessDenied as ex_denied:
            df_logger.warning('Can not kill old process: %s' % ex_denied)
            pass
        except Exception as ex_kill:
            df_logger.error('Can not kill old process: %s' % ex_kill)
    try:
        splashshow = subprocess.Popen(['fim', '--device', '/dev/fb0', '--vt', '1', '--quiet', '--no-commandline',
                                       '-a', '/opt/splash/splash.png'], stdout=log_pipe_out, stderr=log_pipe_err)
        time.sleep(3)
        return splashshow
    except Exception as ex_splash:
        df_logger.error('Can not start splash screen: %s' % ex_splash)
        if CONFIG.DEBUG:
            splashshow = subprocess.Popen(['true'], stdout=log_pipe_out, stderr=log_pipe_err)
            time.sleep(3)
            return splashshow
        pass
    return None


def stop_splashshow(splashshow):
    if splashshow is not None and splashshow.poll() is None:
        splashshow.terminate()


def control_interface(thread_name):
    global RESTART
    global CONFIG
    global TIME_REMIX, TIME_RESYNC
    global stop_control_interface

    while True:
        if stop_control_interface:
            break

        try:
            address = ('localhost', CONFIG.IPC_PORT)  # family is deduced to be 'AF_INET'
            listener = Listener(address, authkey=bytes(CONFIG.WEB_SECRET, 'utf-8'))
            try:
                conn = listener.accept()

                while True:
                    if stop_control_interface:
                        break

                    df_logger.debug('[%s] connection accepted from: %s' % (thread_name, listener.last_accepted))

                    msg = conn.recv()
                    # reload configuration
                    if msg == 'c:reload:setting':
                        df_logger.debug('[%s] reload message received: %s' % (thread_name, msg))
                        CONFIG.reload()
                        RESTART = True
                        conn.send(200)
                        conn.close()
                        break

                    # query stats
                    if msg == 'q:remix:time':
                        df_logger.debug('[%s] reload message received: %s' % (thread_name, msg))
                        conn.send([200, TIME_REMIX])
                    if msg == 'q:resync:time':
                        df_logger.debug('[%s] reload message received: %s' % (thread_name, msg))
                        conn.send([200, TIME_RESYNC])

                    # close connection
                    elif msg == 'close':
                        conn.send(200)
                        conn.close()
                        break

            except Exception as ex_ci:
                df_logger.info('[%s] server error: %s' % (thread_name, str(ex_ci)))

            finally:
                listener.close()

        except Exception as ex_li:
            df_logger.info('[%s] server error, can not listen on interface: %s' % (thread_name, str(ex_li)))


def main():
    global RESTART
    global TIME_REMIX, TIME_RESYNC
    RESTART = False

    df_logger.info('init...')
    # GPIO.setmode(GPIO.BCM)
    # GPIO.setup(PIR_PIN, GPIO.IN)
    # motion_detection_time = get_time()
    slideshow = None
    picture_path_hash = None
    loop_time = 0
    splashshow = start_splashshow()
    turn_off_cursor()
    while True:
        if RESTART:
            RESTART = False
            slideshow = None
            loop_time = 0
            splashshow = start_splashshow()

        # if GPIO.input(PIR_PIN):
        #    motion_detection_time = get_time()
        if slideshow is None:
            picture_path_hash, file_count, sync_time = sync_src()
            TIME_RESYNC = sync_time + CONFIG.SYNC_INTERVAL
            loop_time = file_count * CONFIG.PICTURE_TIMEOUT
            TIME_REMIX = get_time() + loop_time
            slideshow = start_slideshow(splashshow)
            df_logger.info('started (slideshow hash: "' + picture_path_hash
                           + '", remix playlist after ' + str(loop_time / 60) + ' minutes)...')

        # sync photos
        elif slideshow is not None and get_time() > TIME_RESYNC:
            # sync with sync source
            picture_path_hash_new, file_count, sync_time = sync_src()
            TIME_RESYNC = sync_time + CONFIG.SYNC_INTERVAL
            loop_time = file_count * CONFIG.PICTURE_TIMEOUT
            TIME_REMIX = get_time() + loop_time

            # restart if source files had changed
            if picture_path_hash != picture_path_hash_new:
                df_logger.info('source changed ("' + picture_path_hash + '" -> "' + picture_path_hash_new + '")...')
                slideshow = restart_slideshow(slideshow)
                picture_path_hash = picture_path_hash_new
                df_logger.info('restarted (slideshow hash: ' + picture_path_hash + ')...')

        # elif slideshow is not None and get_time() > (motion_detection_time + NO_MOTION_TIMEOUT):
        #    stop_slideshow(slideshow)
        #    slideshow = None

        # restart and remix playlist after each loop
        elif slideshow is not None and CONFIG.RANDOM and get_time() > TIME_REMIX:
            df_logger.info('loop finished after ' + str(loop_time / 60) + ' minutes...')
            TIME_REMIX = get_time() + loop_time
            slideshow = restart_slideshow(slideshow)

        time.sleep(2)


if __name__ == "__main__":
    ipc = None
    log_pipe_out = None
    log_pipe_err = None
    try:
        # init logging
        df_util.init_logger(CONFIG)
        log_pipe_out = df_util.LogPipe(df_logger, logging.DEBUG)
        log_pipe_err = df_util.LogPipe(df_logger, logging.WARNING)

        # start ipc thread
        ipc = threading.Thread(target=control_interface, args=('ipc',))
        ipc.daemon = True
        ipc.start()

        # start slide show
        main()
    except KeyboardInterrupt:
        df_logger.critical('Stopping user aborted with CTRL+C')
        # GPIO.cleanup()

    except Exception as ex:
        df_logger.critical('Fatal error: %s', ex)

    finally:
        stop_control_interface = True
        if ipc is not None:
            ipc.join(1)
        if log_pipe_out is not None:
            log_pipe_out.close()
        if log_pipe_err is not None:
            log_pipe_err.close()
        sys.exit()
