from os import environ as os_environ

SECRET_KEY_BYTES = os_environ.get('SECRET_KEY').encode()