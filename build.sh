#!/bin/sh

# Navigate to current folder
cd "$(dirname "$0")"/bcc || exit

mvn clean package