#!/bin/sh
# Move to the directory where the script is located
cd "$(dirname "$0")" || exit

./debug.sh $@