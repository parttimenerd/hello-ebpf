#!/bin/zsh

# Navigate to current folder
cd "$(dirname "$0")"/bpf || exit

# if empty arguments or help flag, print help
if [ $# -eq 0 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "Usage: $0 <sample>"
    echo "Available samples:"
    (cd src/main/java/me/bechberger/ebpf/samples && (
      find . -name "*.java" | while read file; do
        f=$(echo "$file" | sed 's/\//\./g')
        f=${f:2}
        printf "%-35s - " "${f%.java}"
        awk '/\/\*\*/{getline; sub(/^ \* /, ""); print; exit}' "$file"
      done
    ))
    exit 0
fi

CLASS=$1

# Run the program
shift
java --enable-preview -cp target/bpf.jar --enable-native-access=ALL-UNNAMED $JAVA_OPTS me.bechberger.ebpf.samples.$CLASS $@