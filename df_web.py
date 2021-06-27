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

import re
import urllib.parse
import df_util
import stat
import os
from io import BytesIO
from datetime import datetime
from PIL import Image, ImageOps, ExifTags
from multiprocessing.connection import Client

from flask import Flask, render_template, jsonify, json, request, flash, redirect, \
    url_for, send_from_directory, send_file
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin
from werkzeug.serving import run_simple

# config
CONFIG = df_util.Config()

ASSETS_DIR = os.path.dirname(os.path.abspath(__file__))
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
# set to True to inform that the app needs to be re-created
RELOAD_APP = False

global_msg = []

# read config file
if len(CONFIG.files) == 0:
    global_msg_error = 'Config file not found, using default settings!'
    global_msg += [(global_msg_error, 'danger')]
    print(global_msg_error)

cert = CONFIG.WEB_SSL_CERT
key = CONFIG.WEB_SSL_KEY

time_format = CONFIG.GLOBAL_TIME_FORMAT
picture_path = CONFIG.PICTURE_PATH
picture_cache_path = CONFIG.WEB_THUMBNAIL_CACHE_PATH
use_picture_cache = CONFIG.WEB_THUMBNAIL_CACHE

if os.path.isfile(cert) and os.path.isfile(key):
    context = (cert, key)  # certificate and key files
else:
    if CONFIG.WEB_SSL:
        global_msg_error = 'SSL certificate not found, using HTTP!'
        global_msg += [(global_msg_error, 'danger')]
        print("+++ ERROR: SSL certificate files '%s', '%s' not found!" % (cert, key))
    context = None

try:
    import logging

    logger = logging.getLogger('waitress')
    logger.setLevel(logging.INFO)
except Exception as ex_waitress:
    print('+++ can not init waitress logger: %s' % ex_waitress)
    pass


class User(UserMixin):  # db.Document):
    global CONFIG
    config_user = df_util.ConfigUser(CONFIG)

    id = '99999'
    active = False
    name = 'guest'
    email = 'guest@localhost'
    description = 'Guest'
    password = None
    authenticated = False

    def to_json(self):
        return {"id": self.id,
                "active": self.active,
                "name": self.name,
                "email": self.email,
                "description": self.description}

    def is_authenticated(self):
        if not self.active or self.password is None:
            return False  # Guest account / no password
        return self.authenticated

    def is_active(self):
        return self.active

    def is_anonymous(self):
        if str(self.id).lower() == '-1':
            return True
        return False

    def get_id(self):
        return str(self.id)

    def check_password(self, password):
        if self.active:
            if self.config_user.is_correct_password(self.password, password):
                self.authenticated = True
                return self.authenticated
        self.authenticated = False
        return False

    def __load_user_data(self, user):
        if user:
            self.id = user['id']
            self.active = user['active']
            self.name = user['name']
            self.email = user['email']
            self.description = user['description']
            self.password = user['password']
            return self
        return None

    def query_by_id(self, user_id: str):
        user = self.config_user.get_user_by_id(user_id)
        return self.__load_user_data(user)

    def query(self, user_name: str):
        user = self.config_user.get_user(user_name)
        return self.__load_user_data(user)


def call_system_command(command):
    global CONFIG

    try:
        address = ('localhost', CONFIG.SYS_IPC_PORT)
        conn = Client(address, authkey=bytes(CONFIG.WEB_SECRET, 'utf-8'))
        try:
            conn.send(command)
            (status, msg) = conn.recv()
            resp = {"result": status,
                    "data": {"message": msg}}
        except Exception as e:
            resp = {"result": 404,
                    "data": {"message": "Can not connect to system service: %s" % e}}
        finally:
            if conn is not None:
                conn.close()
    except Exception as e:
        resp = {"result": 408,
                "data": {"message": "request timeout, cannot connect to system service: %s" % e}}

    return jsonify(**resp)


def get_thumbnail(picture, base_width, base_height):
    src_pic = os.path.join(picture_path, picture)
    pic_cache = None
    if use_picture_cache:
        src_stat = os.stat(src_pic)
        src_mtime = src_stat[stat.ST_MTIME]

        if os.path.exists(picture_cache_path):
            # use cache
            if base_width is None:
                path_cache = os.path.join(picture_cache_path, 'h' + str(base_height))
            else:
                path_cache = os.path.join(picture_cache_path, 'w' + str(base_width))

            pic_cache = os.path.join(path_cache, picture)
            if os.path.exists(pic_cache):
                cache_stat = os.stat(pic_cache)
                cache_mtime = cache_stat[stat.ST_MTIME]

                if src_mtime < cache_mtime:
                    return send_file(pic_cache)
        else:
            flash('Thumbnail cache was enabled but "%s" was not found!' % picture_cache_path, 'danger')

    try:
        img = Image.open(src_pic)
    except Exception as ex:
        flash('Can not open image \'%s\': %s' % (src_pic, str(ex)), 'danger')
        return

    # fix orientation
    try:
        img = ImageOps.exif_transpose(img)
    except Exception as exr:
        logger.debug('Fallback to Exif- Rotate \'%s\': %s' % (src_pic, str(exr)))
        # flash('Fallback to Exif- Rotate \'%s\': %s' % (src_pic, str(exr)), 'warning')
        # fallback to manual rotate
        for orientation in ExifTags.TAGS.keys():
            if ExifTags.TAGS[orientation] == 'Orientation':
                try:
                    exif = img._getexif()
                    if exif[orientation] == 3:
                        img = img.rotate(180, expand=True)
                    elif exif[orientation] == 6:
                        img = img.rotate(270, expand=True)
                    elif exif[orientation] == 8:
                        img = img.rotate(90, expand=True)
                except Exception as ex_re:
                    logger.debug('Error in Exif- Rotate \'%s\': %s' % (src_pic, str(ex_re)))
                    # flash('Error in Exif- Rotate \'%s\': %s' % (src_pic, str(ex_re)), 'warning')
                    pass
                break

    # original size
    width = int(img.size[0])
    height = int(img.size[1])
    try:
        if base_height is not None:
            h_percent = (float(base_height) / height)
            height = int(base_height)
            width = int(float(width) * float(h_percent))
        elif base_width is not None:
            w_percent = (float(base_width) / width)
            height = int(float(height) * float(w_percent))
            width = int(base_width)
    except Exception as exs:
        flash('Resize failed \'%s\': %i x %i \n%s' % (src_pic, width, height, str(exs)), 'warning')

    img = img.resize((width, height), Image.ANTIALIAS)

    if use_picture_cache and pic_cache:
        path_cache_sub = os.path.dirname(pic_cache)
        os.makedirs(path_cache_sub, exist_ok=True)
        try:
            img.save(pic_cache)
        except Exception as ex:
            flash('Can not cache thumbnail \'%s\'! %s' % (pic_cache, str(ex)), 'danger')

    data = BytesIO()
    img.save(data, 'JPEG')
    img.close()

    data.seek(0)
    return send_file(data, mimetype='image/jpeg')


def get_app():
    global CONFIG

    # to make sure of the new app instance
    app_started = datetime.now(tz=CONFIG.time_zone())
    print("create app now: %s" % app_started)

    app = Flask(__name__)

    # flask/web configuration
    app.static_url_path = ''
    app.static_folder = os.path.abspath(CONFIG.WEB_STATIC_PATH)
    app.template_folder = os.path.abspath(CONFIG.WEB_TEMPLATES_PATH)
    app.secret_key = CONFIG.WEB_SECRET

    login_manager = LoginManager()
    login_manager.login_view = 'login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        """Check if user is logged-in on every page load."""
        if user_id is not None:
            return User().query_by_id(user_id)  # .query.get(user_name)
        return None

    @login_manager.unauthorized_handler
    def unauthorized():
        """Redirect unauthorized users to Login page."""
        flash('You must be logged in to view that page.', 'danger')
        return redirect(url_for('login'))

    @app.context_processor
    def inject_now():
        try:
            for msg, cat in global_msg:
                flash(msg, cat)
        except ValueError as ex:
            print('+++ ERROR [inject_now]: %s' % ex)
            for msg in global_msg:
                flash(msg, 'danger')

        return {'now': datetime.now(tz=CONFIG.time_zone()),
                'logo': CONFIG.WEB_LOGO,
                'theme_color': CONFIG.WEB_THEME_COLOR,
                'theme_color_url': urllib.parse.quote_plus(CONFIG.WEB_THEME_COLOR),
                'system_name': CONFIG.GLOBAL_SYS_NAME
                }

    @app.route('/login', methods=['POST', 'GET'])
    def login():
        if request.method == 'POST':
            # Bypass if user is logged in
            if current_user.is_authenticated:
                next_page = request.args.get('next')
                return redirect(next_page or url_for('index'))

            if len(request.form) > 0:
                username = request.form.get('username')
                password = request.form.get('password')
            else:
                info = json.load(request.data)
                username = info.get('username', 'guest')
                password = info.get('password', '')

            # Login
            user = User().query(username)  # .objects(name=username, password=password).first()
            if user:
                if user.check_password(password):
                    login_user(user)
                    flash('Logged in successfully', 'success')
                    next_page = request.args.get('next')
                    return redirect(next_page or url_for('index'))
                    # return jsonify(user.to_json())

            error_msg = 'Invalid username/password combination'
            if len(request.form) > 0:
                flash(error_msg, 'warning')
                return render_template('login.html', nav_active_login='active', error=error_msg)
            else:
                return jsonify({"status": 401,
                                "reason": error_msg})
        else:
            return render_template('login.html', nav_active_login='active')

    @app.route('/logout', methods=['POST', 'GET'])
    def logout():
        logout_user()
        if request.method == 'POST':
            return jsonify(**{'result': 200,
                              'data': {'message': 'logout success'}})
        else:
            flash('You were successfully logged out', 'info')
            return redirect(url_for('login'))

    @app.route('/user_info', methods=['POST'])
    @login_required
    def user_info():
        if current_user.is_authenticated:
            resp = {"result": 200,
                    "data": current_user.to_json()}
        else:
            resp = {"result": 401,
                    "data": {"message": "user no login"}}
        return jsonify(**resp)

    @app.route("/profile", methods=['POST', 'GET'])
    @login_required
    def profile():
        global CONFIG
        config_user = df_util.ConfigUser(CONFIG)
        if request.method == 'POST':
            if len(request.form) > 0:
                form = request.form
                user_id = form.get('user_id')
                user = config_user.get_user_by_id(user_id)
                error_fields = []
                if user:
                    user['active'] = form.get('user_active')
                    user['name'] = form.get('user_name')
                    user['email'] = form.get('user_email')
                    user['description'] = form.get('user_description')
                    password = form.get('user_password')
                    if password and password.strip().lower() != '########':
                        # old password was provided -> change password
                        password_new = form.get('user_password_new')
                        password_repeat = form.get('user_password_repeat')
                        if config_user.is_correct_password(user['password'], password):
                            # old password is correct
                            if len(password_new) > 5:
                                if password_new == password_repeat:
                                    password = config_user.hash_new_password(password_new)
                                    user['password'] = password
                                else:
                                    error_fields.append('user_password_new')
                                    error_fields.append('user_password_repeat')
                                    flash('Passwords are different, please check new passwords (Typo?)!', 'danger')
                            else:
                                error_fields.append('user_password_new')
                                error_fields.append('user_password_repeat')
                                flash('New password have to be at least 5 characters long!', 'danger')
                        else:
                            error_fields.append('user_password')
                            flash('Invalid old password provided.', 'danger')

                        return render_template('profile.html',
                                               user=user, error_fields=error_fields,
                                               password_new=password_new, password_repeat=password_repeat,
                                               nav_active_profile_menu='active', nav_active_profile='active')
                    if CONFIG.save():
                        flash('User "%s" was successfully updated, please logoff and login again!'
                              % user['name'], 'info')
                    else:
                        flash('User "%s" was not updated! Check logs for further information.' % user['name'], 'danger')

                else:
                    flash('User with ID "%s" not found!' % user_id, 'danger')
            else:
                info = json.load(request.data)
                print(info)
        return render_template('profile.html', user=current_user,
                               nav_active_profile_menu='active', nav_active_profile='active')

    @app.route("/users", methods=['POST', 'GET'])
    @login_required
    def users():
        global CONFIG
        config_users = df_util.ConfigUser(CONFIG)
        if request.method == 'POST':
            if len(request.form) > 0:
                # update and create via form data
                form_users = {
                    'new': dict(),
                    'user': dict(),
                    'count': 0
                }

                for field, value in request.form.items():
                    if not re.match(r'^clone_', field):
                        (field_type, field_index, field_name) = re.findall(r'^(new|user)_(\d+)_(.*)$', field)[0]
                        if field_index not in form_users[field_type]:
                            form_users[field_type][field_index] = dict()
                            form_users['count'] += 1
                        form_users[field_type][field_index][field_name] = value

                if form_users['count'] > 0:
                    # add new users
                    count_new = 0
                    for name, user in form_users['new'].items():
                        password = user['password']
                        if password and password.strip().lower() != '########':
                            user['password'] = config_users.hash_new_password(password)
                        status, message, message_type = config_users.append_user(user)
                        if status:
                            count_new += 1
                            flash(message, message_type)
                        else:
                            flash(message, message_type)

                    # update users
                    count_update = 0
                    for name, user in form_users['user'].items():
                        config_user = config_users.get_user_by_id(user['id'])
                        if config_user:
                            if 'active' in user:
                                config_user['active'] = True
                            else:
                                config_user['active'] = False
                            config_user['name'] = user['name']
                            config_user['email'] = user['email']
                            config_user['description'] = user['description']
                            password = user['password']
                            if password and password.strip().lower() != '########':
                                config_user['password'] = config_users.hash_new_password(password)
                            count_update += 1
                            flash('User "%s" was successfully updated!' % config_user['name'], 'info')

                    if count_new + count_update > 0:
                        if CONFIG.save():
                            if form_users['count'] == count_new + count_update:
                                flash('User list was successfully updated!', 'info')
                            else:
                                flash('User list was partially updated, '
                                      'please check previous messages for further information!', 'warning')
                        else:
                            flash('User list was not updated, please check log messages for further information!',
                                  'danger')

                    else:
                        CONFIG.reload()
                        flash('User list was not updated, please check previous messages for further information!',
                              'danger')
                else:
                    flash('Nothing to change!', 'info')

            else:
                # delete via json message
                data = request.json
                if 'func' in data:
                    json_func = data['func']
                    if json_func == 'delete':
                        if 'uid' in data:
                            uid = data['uid']
                            user = config_users.get_user_by_id(uid)
                            if user:
                                user_name = user['name']
                                if len(config_users.get_users()) > 1:
                                    if config_users.remove_user_by_id(uid):
                                        resp = {"result": 200,
                                                "data": {"message": "User '%s' was removed!"
                                                                    % user_name, "uid": uid}}
                                    else:
                                        resp = {"result": 401,
                                                "data": {"message": "User '%s' was not removed!"
                                                                    % user_name, "uid": uid}}
                                else:
                                    resp = {"result": 402,
                                            "data": {"message": "User '%s' cannot be removed, this is our last user!"
                                                                % user_name, "uid": uid}}
                            else:
                                resp = {"result": 404,
                                        "data": {"message": "User with ID '%s' not found!" % uid}}
                        else:
                            resp = {"result": 500,
                                    "data": {"message": "No user ID provided (UID)!"}}
                    else:
                        resp = {"result": 501,
                                "data": {"message": "Unknown function: %s" % json_func}}
                else:
                    resp = {"result": 502,
                            "data": {"message": "Call without function!"}}
                return jsonify(**resp)
        return render_template('users.html', users=config_users.get_users(), config=CONFIG, current_user=current_user,
                               nav_active_users='active', nav_active_settings_menu='active')

    @app.route("/settings", methods=['POST', 'GET'])
    @login_required
    def settings():
        global CONFIG
        selected_section = ''
        for section in CONFIG.SETTINGS:
            active = True
            if '_section' in CONFIG.SETTINGS[section] and 'enabled' in CONFIG.SETTINGS[section]['_section']:
                active = CONFIG.SETTINGS[section]['_section']['enabled']
            if active:
                selected_section = section
                break

        if request.method == 'POST':
            if len(request.form) > 0:
                logger.debug(request.form)

                for section_name in CONFIG.SETTINGS:
                    section = CONFIG.SETTINGS[section_name]
                    for option_name in section:
                        setting_key = section_name + '__' + option_name
                        value = None
                        if setting_key in request.form:
                            value = request.form[setting_key]

                        new_value = CONFIG.set_option(section=section_name, option=option_name, value=value)
                        logger.debug('Updated setting "%s" with "%s" ("%s")' % (setting_key, new_value, value))

                if CONFIG.save():
                    flash('Settings was successfully updated!', 'info')

                    # reload web server settings
                    global time_format, picture_path
                    CONFIG.reload()
                    time_format = CONFIG.GLOBAL_TIME_FORMAT
                    picture_path = CONFIG.PICTURE_PATH

                    # reload slideshow settings
                    address = ('localhost', CONFIG.IPC_PORT)
                    try:
                        conn = Client(address, authkey=bytes(CONFIG.WEB_SECRET, 'utf-8'))
                        try:
                            conn.send('c:reload:setting')
                            status = conn.recv()
                            if status == 200:
                                logger.info("Slideshow settings was successfully reloaded")
                            else:
                                logger.info("Slideshow settings was not reloaded: %s" % status)
                        except Exception as e:
                            flash("Request timeout, cannot connect to console service: %s" % e, 'danger')

                        finally:
                            if conn is not None:
                                conn.close()
                    except Exception as e:
                        flash("Cannot connect to console service: %s" % e, "danger")
                else:
                    flash('Settings was not updated! Check logs for further information.', 'danger')
            else:
                data = request.json
                logger.debug(data)

        return render_template('settings.html', config=CONFIG,
                               selected_section=selected_section,
                               nav_active_settings_menu='active',
                               nav_active_settings='active')

    @app.route('/restart-webserver', methods=['POST'])
    @login_required
    def restart_web():
        global RELOAD_APP
        RELOAD_APP = True
        resp = {"result": 200,
                "data": {"message": "Restarting Webserver, please wait..."}}
        return jsonify(**resp)

    @app.route("/shutdown", methods=['POST'])
    @login_required
    def shutdown():
        return call_system_command('c:system:shutdown')

    @app.route("/reboot", methods=['POST'])
    @login_required
    def reboot():
        return call_system_command('c:system:restart')

    @app.route("/settings-slideshow-reload", methods=['POST'])
    @login_required
    def settings_slideshow_reload():
        global CONFIG
        address = ('localhost', CONFIG.IPC_PORT)
        try:
            conn = Client(address, authkey=bytes(CONFIG.WEB_SECRET, 'utf-8'))
            try:
                conn.send('c:reload:setting')
                status = conn.recv()
                resp = {"result": status,
                        "data": {"message": "new slideshow settings, was loaded"}}
            except Exception as e:
                resp = {"result": 408,
                        "data": {"message": "request timeout, cannot connect to console service: %s" % e}}

            finally:
                if conn is not None:
                    conn.close()
        except Exception as e:
            resp = {"result": 404,
                    "data": {"message": "cannot connect to console service: %s" % e}}

        return jsonify(**resp)

    @app.route("/settings-web-reload", methods=['POST'])
    @login_required
    def settings_web_reload():
        global CONFIG
        resp = {"result": 200,
                "data": {"message": "new web settings, was loaded"}}
        if CONFIG.reload() == 0:
            resp = {"result": 401,
                    "data": {"message": "config file not found, using default values"}}

        # reload global settings
        global time_format, picture_path
        CONFIG.reload()
        time_format = CONFIG.GLOBAL_TIME_FORMAT
        picture_path = CONFIG.PICTURE_PATH
        return jsonify(**resp)

    @app.route("/gallery/<path:picture>")
    def gallery(picture):
        pic = os.path.join(picture_path, picture)

        if not os.path.exists(pic):
            msg = 'Picture "' + picture + '" not found'
            flash(msg, 'warning')
            resp = {"result": 404,
                    "data": {"message": msg}}
            return jsonify(**resp)

        height = None
        width = None
        if request:
            height = request.values.get('height', None)
            width = request.values.get('width', None)

        try:
            return get_thumbnail(picture, width, height)
        except Exception as e:
            flash('Error: Can not get thumbnail (\'%s\')! %s' % (picture, str(e)), 'danger')

        return send_from_directory(picture_path, picture)

    @app.route("/pictures")
    def pictures():
        global CONFIG
        picture_list = df_util.get_file_list(picture_path, web_mode=True)
        picture_list = [(w[0].replace(picture_path, ''), w[1],
                         datetime.fromtimestamp(w[2], tz=CONFIG.time_zone()).strftime(time_format),
                         w[3])
                        for w in picture_list]
        return render_template('pictures.html',
                               pictures=picture_list, sync_mode=CONFIG.SYNC_MODE,
                               nav_active_pictures='active')

    @app.route("/<path:path>")
    def static_default(path):
        return send_from_directory(app.static_folder, path)

    @app.route("/")
    def index():
        global CONFIG

        sys_time_fmt = datetime.now(tz=CONFIG.time_zone()).strftime(time_format)

        sys_uptime = df_util.get_sys_uptime()
        sys_uptime_tz = datetime.utcfromtimestamp(sys_uptime)
        sys_up_days = int(sys_uptime / 86400)
        sys_uptime_fmt = str(sys_up_days) + sys_uptime_tz.strftime('d %Hh %Mm') + " (%.2f h)" % (sys_uptime / 60 / 60)

        sys_webserver_uptime = (datetime.now(tz=CONFIG.time_zone()) - app_started).total_seconds()
        sys_webserver_uptime_tz = datetime.utcfromtimestamp(sys_webserver_uptime)
        sys_webserver_up_days = int(sys_webserver_uptime / 86400)
        sys_webserver_uptime_fmt = str(sys_webserver_up_days) + sys_webserver_uptime_tz.strftime(
            'd %Hh %Mm') + " (%.2f h)" % (sys_webserver_uptime / 60 / 60)

        picture_list = df_util.get_file_list(CONFIG.PICTURE_PATH, web_mode=True)
        picture_loop_duration = CONFIG.PICTURE_TIMEOUT * len(picture_list)

        time_remix_str = '-'
        time_resync_str = '-'
        picture_loop_time_left = picture_loop_duration
        sync_resync_time_left = CONFIG.SYNC_INTERVAL
        try:
            address = ('localhost', CONFIG.IPC_PORT)
            conn = Client(address, authkey=bytes(CONFIG.WEB_SECRET, 'utf-8'))
            if CONFIG.RANDOM:
                try:
                    conn.send('q:remix:time')
                    status, time_remix = conn.recv()
                    time_remix_str = datetime.fromtimestamp(time_remix).strftime(time_format)
                    picture_loop_time_left = time_remix - datetime.now(tz=CONFIG.time_zone()).timestamp()
                except Exception as e:
                    logger.error("Can not query remix time from console service: %s" % e)
            else:
                time_remix_str = '-'
            if CONFIG.SYNC_MODE != CONFIG.SYNC_MODE_NONE:
                try:
                    conn.send('q:resync:time')
                    status, time_resync = conn.recv()
                    conn.send('close')
                    time_resync_str = datetime.fromtimestamp(time_resync).strftime(time_format)
                    sync_resync_time_left = time_resync - datetime.now(tz=CONFIG.time_zone()).timestamp()
                except Exception as e:
                    logger.error("Can not query resync time from console service: %s" % e)
            else:
                time_resync_str = '-'
            if conn:
                conn.send('close')
                conn.close()
        except Exception as e:
            if CONFIG.WEB_DEBUG:
                if CONFIG.RANDOM:
                    time_remix = datetime.now().timestamp() + 500
                    time_remix_str = datetime.fromtimestamp(time_remix).strftime(time_format)
                    picture_loop_time_left = time_remix - datetime.now(tz=CONFIG.time_zone()).timestamp()
                else:
                    time_remix_str = '-'

                if CONFIG.SYNC_MODE != CONFIG.SYNC_MODE_NONE:
                    time_resync = datetime.now().timestamp() + 500
                    time_resync_str = datetime.fromtimestamp(time_resync).strftime(time_format)
                    sync_resync_time_left = time_resync - datetime.now(tz=CONFIG.time_zone()).timestamp()
                else:
                    time_resync_str = '-'

            logger.error("Can not connect to console service: %s" % e)

        if picture_loop_duration:
            picture_loop_percent = (picture_loop_duration - picture_loop_time_left) / picture_loop_duration * 100
        else:
            picture_loop_percent = 0

        return render_template('base.html',
                               sys_time=sys_time_fmt,
                               sys_uptime=sys_uptime_fmt,
                               sys_webserver_uptime=sys_webserver_uptime_fmt,
                               sys_disk_stat=df_util.get_sys_disk_usage(None),
                               sys_stat=df_util.get_sys_stat(),
                               stat_pic_count=len(picture_list),
                               stat_pic_timeout=CONFIG.PICTURE_TIMEOUT,
                               stat_pic_duration=picture_loop_duration,
                               stat_pic_remix=time_remix_str,
                               stat_pic_remix_info='%.0f / %.0f min (%.0f left)' % (
                                   (picture_loop_duration - picture_loop_time_left) / 60, picture_loop_duration / 60,
                                   picture_loop_time_left / 60),
                               stat_pic_remix_percent=picture_loop_percent,
                               stat_pic_path=CONFIG.PICTURE_PATH,
                               stat_sync_mode=CONFIG.SYNC_MODE,
                               stat_sync_source=CONFIG.SYNC_SOURCE,
                               stat_sync_interval=CONFIG.SYNC_INTERVAL,
                               stat_sync_resync=time_resync_str,
                               stat_sync_resync_info='%.0f / %.0f min (%.0f left)' % (
                                   (CONFIG.SYNC_INTERVAL - sync_resync_time_left) / 60, CONFIG.SYNC_INTERVAL / 60,
                                   sync_resync_time_left / 60),
                               stat_sync_resync_percent=(CONFIG.SYNC_INTERVAL - sync_resync_time_left
                                                         ) / CONFIG.SYNC_INTERVAL * 100,
                               )

    return app


class AppLoader(object):
    def __init__(self, create_app):
        self.create_app = create_app
        self.app = create_app()

    def get_application(self):
        global RELOAD_APP
        if RELOAD_APP:
            self.app = self.create_app()
            RELOAD_APP = False
        return self.app

    def __call__(self, environ, start_response):
        app = self.get_application()
        return app(environ, start_response)


application = AppLoader(get_app)
if __name__ == "__main__":
    # init logging
    logger = df_util.init_logger(CONFIG)

    # start web server
    # debug=CONFIG.WEB_DEBUG,
    max_processes = 1
    if not CONFIG.WEB_DEBUG:
        max_processes = df_util.get_sys_cores()
    run_simple(hostname=CONFIG.WEB_HOST,
               application=application,
               port=CONFIG.WEB_PORT,
               ssl_context=context,
               processes=max_processes,
               use_debugger=True,
               use_evalex=True,
               use_reloader=True)
