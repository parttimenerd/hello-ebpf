#!/usr/bin/env sh

set -e

# get parent-parent folder, shell agnostic
cd "$(dirname "$0")"/.. || exit

(cd bpf-runtime; mvn clean)

mvn -pl '!bpf' package && time java -jar bpf-gen/target/bpf-gen.jar bpf-runtime/src/main/java/ bpf-gen/data/helper-defs.json