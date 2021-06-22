#!/bin/sh
# get splash picture from config or use fallback
# DF_SPLASH=
if [ -r /etc/default/digiframe ]; then
        . /etc/default/digiframe
fi
[ -f "${DF_SPLASH}" ] || DF_SPLASH=/opt/digiframe/static/splash.png
/usr/bin/fim --device /dev/fb0 --vt 1 --quiet --no-commandline -a ${DF_SPLASH} > /dev/null 2>&1
