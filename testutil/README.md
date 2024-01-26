Test Utils
==========

This directory contains utilities for testing the compiler and runtime.
More information on the scripts can be found in the
headers of the scripts themselves.

- [`bin/java`](bin/java): wrap Java, so it runs in a container
- [`run-in-container.sh`](run-in-container.sh): run a command in a virt-me container
- [`find_and_get_kernel.sh`](find_and_get_kernel.sh): download kernel headers

Requirements
------------
- docker
  - current user should be able to run docker, so `sudo usermod -aG docker $USER; newgrp docker`
- [virtme](https://github.com/ezequielgarcia/virtme): runs a virtualized kernel, `apt install virtme` or `pip3 install virtme`
- [qemu](https://www.qemu.org/): runs the virtualized kernel, `apt install qemu-system-x86`
- python3 to run the header download script
- debian based distro (uses `dpkg-deb` to extract kernel headers)


License
-------
MIT