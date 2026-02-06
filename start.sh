#!/bin/sh
set -eu

mkdir -p /tmp/jobs

# single worker/thread to keep RAM predictable
exec gunicorn -w 1 -k gthread --threads 1 --timeout 240 -b 0.0.0.0:8080 app:app
