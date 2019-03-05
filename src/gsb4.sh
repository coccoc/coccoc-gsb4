#!/bin/bash

# make logs dir if not exists
LOGDIR=/var/log/coccoc-gsb4
mkdir -p $LOGDIR
MAIL_TO="quannk@coccoc.com"

export APPLICATION_START_TIME=`eval date +%Y-%m-%d_%H.%M.%S`

# remove 30 days old logs
find $LOGDIR -type f -name 'gsb_*log' -mtime +30 -exec rm {} \;

# run
log_file="$LOGDIR/gsb_${APPLICATION_START_TIME}.log"
perl -w /usr/bin/gsb4.pl 2> $log_file

retVal=$?
if [ $retVal -ne 0 ]; then
    # print error message to stdout and mail
    echo "Error when update gsb $retVal. See log `realpath $log_file`" | tee /dev/tty | mail -s "Error when update gsb4" $MAIL_TO
    exit $retVal
fi