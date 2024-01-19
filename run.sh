#!/bin/zsh

# Navigate to current folder
cd "$(dirname "$0")"/bcc || exit

# if empty arguments or help flag, print help
if [ $# -eq 0 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "Usage: $0 <sample>"
    echo "Available samples:"
    (cd src/main/java/me/bechberger/ebpf/samples && (
      find . -name "*.java" | while read file; do
        f=$(echo "$file" | sed 's/\//\./g')
        f=${f:2}
        printf "%-35s - %s\n" "${f%.java}" "$(head -n 2 "$file" | tail -n 1 | sed 's/^ \* //g')"
      done
    ))
    exit 0
fi

CLASS=$1

# Run the program
shift
java --enable-preview -cp target/bcc.jar --enable-native-access=ALL-UNNAMED $JAVA_OPTS me.bechberger.ebpf.samples.$CLASS $@