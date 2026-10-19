#!/bin/sh
# Inicializa la BD (idempotente) y arranca gunicorn. Las credenciales llegan por entorno.
set -eu
python create_db.py
exec gunicorn --bind 0.0.0.0:5000 --workers 2 --access-logfile - app:app
