#!/bin/bash
sed "/#\$nrconf{restart} = 'i';/s/.*/\$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf
apt-get update
apt-get install -y apt-transport-https ca-certificates curl clang llvm jq maven
apt-get install -y libelf-dev libpcap-dev libbfd-dev binutils-dev build-essential make
apt-get install -y linux-tools-common linux-tools-$(uname -r)
apt-get install -y bpfcc-tools libbpfcc-dev libbpf-dev
apt-get install -y python3-pip zsh tmux openjdk-22-jre-headless