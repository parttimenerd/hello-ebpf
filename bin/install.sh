#!/bin/bash
sudo bash -c "echo \"\\\$nrconf{restart} = 'a'\" >> /etc/needrestart/needrestart.conf"
sudo apt-get install -y apt-transport-https ca-certificates curl clang llvm
sudo apt-get install -y libelf-dev libpcap-dev libbfd-dev binutils-dev build-essential make
sudo apt-get install -y linux-tools-common linux-tools-$(uname -r)
sudo apt-get install -y bpfcc-tools libbpfcc-dev libbpf-dev
sudo apt-get install -y python3-pip zsh tmux
sudo apt-get install -y zip unzip git
curl -s "https://get.sdkman.io" | bash
source "$HOME/.sdkman/bin/sdkman-init.sh"
sdk install java 22-sapmchn
sdk install maven