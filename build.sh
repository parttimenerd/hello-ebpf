#!/bin/sh

cd "$(dirname "$0")" || exit

mvn package -DskipTests=true