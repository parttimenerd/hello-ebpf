#!/bin/sh
# Move to the directory where the script is located
cd "$(dirname "$0")"/bcc || exit

# if empty arguments or help flag, print help of ./run.sh and prefix with "debug port is "5005"
if [ $# -eq 0 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "Usage: $0 <sample>"
    echo "Debug port is 5005"
    ../run.sh | tail -n +2
    exit 0
fi

# Run the program with debug port 5005
JAVA_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=*:5005" ../run.sh "$1"