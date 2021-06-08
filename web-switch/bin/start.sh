#!/bin/sh

WEB_SWITCH_HOME=$(dirname $(pwd))
/usr/local/openresty/nginx/sbin/nginx -p $WEB_SWITCH_HOME -c $WEB_SWITCH_HOME/etc/nginx.conf -g 'daemon off;'
