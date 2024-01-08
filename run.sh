#!/bin/sh

# Navigate to current folder
cd "$(dirname "$0")"/bcc || exit

# if empty arguments or help flag, print help
if [ $# -eq 0 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "Usage: $0 <sample>"
    echo "Available samples:"
    (cd src/main/java/me/bechberger/ebpf/samples && (
      for file in **/*.java; do
        f=$(echo "$file" | sed 's/\//\./g')
        printf "%-30s - %s\n" "${f%.java}" "$(head -n 2 "$file" | tail -n 1 | sed 's/^ \* //g')"
      done
    ))
    exit 0
fi
# Run the program
java --enable-preview -cp target/bcc.jar --enable-native-access=ALL-UNNAMED $JAVA_OPTS me.bechberger.ebpf.samples.$1