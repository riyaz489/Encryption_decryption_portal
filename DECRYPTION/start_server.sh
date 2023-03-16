#!/bin/bash

NAME="Decryption_portal"
DJANGODIR=/home/ubuntu/app
NUM_WORKERS=3
DJANGO_SETTINGS_MODULE=DecryptionPortal.settings
DJANGO_WSGI_MODULE=DecryptionPortal.wsgi
LOG_LEVEL=debug
cd $DJANGODIR
export DJANGO_SETTINGS_MODULE=$DJANGO_SETTINGS_MODULE
export PYTHONPATH=$DJANGODIR:$PYTHONPATH
export PATH=$PATH:/usr/local/bin
export DEBUG=false
python manage.py migrate --noinput
python manage.py ldap_sync_users
python manage.py collectstatic --noinput -c
echo "from django.contrib.auth.models import User; User.objects.create_superuser('admin', 'admin@examle.com','pass')" | python manage.py shell || true
exec /usr/local/bin/gunicorn ${DJANGO_WSGI_MODULE}:application \
--name $NAME --workers $NUM_WORKERS \
--bind 0.0.0.0:8000 --log-level=$LOG_LEVEL --log-file=-