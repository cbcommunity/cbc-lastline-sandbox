#
# This file is for enabling the execution loop in the Docker container.
# Change the LOOP_MINUTES varaible to a value between 1 and 60.
#

#!/bin/bash

# Enter the number of minutes to check for new emails. Max = 60 minutes
LOOP_MINUTES=15

cd /app
tail -f app.log &

echo "Docker container has been started" >> app.log

pip install --upgrade pip
pip install -r /code/requirements.txt

if [ -z ${LAST_PULL+x} ]; then LAST_PULL="None"; fi
if [ -z ${START_TIME+x} ]; then START_TIME="None"; fi
if [ -z ${END_TIME+x} ]; then END_TIME="None"; fi

CRON="$(($LOOP_MINUTES * 60))"
while :
    do python app.py --last-pull $LAST_PULL --start-time $START_TIME --end-time $END_TIME >> app.log 2>&1
    sleep $CRON
done