#!/bin/sh

cd "$(dirname "$0")" || exit

(cd annotations && mvn install)

(cd bcc && mvn package)