# Task 3 - Digging deeper - (Reverse Engineering)

The network administrators confirm that the IP address you provided in your description is an edge router. DAFIN-SOC is asking you to dive deeper and reverse engineer this device. Fortunately, their team managed to pull a memory dump of the device.

Scour the device's memory dump and identify anomalous or malicious activity to find out what's going on.

Your submission will be a list of IPs and domains, one per line. For example:
```
127.0.0.1 localhost
192.168.54.131 corp.internal
```
...
</span>


## Downloads

  - [Memory Dump (memory.dump.gz)](Downloads/memory.dump.gz)
  - [Metadata (System.map.br)](Downloads/System.map.br)
  - [Kernel Image (vmlinux.xz)](Downloads/vmlinux.xz)

## Prompt

    Submit a complete list of affected IPs and FQDNs, one per line.

## Solution

The first step necessary is to extract each of the source files. Use `7zip` on Windows for the `.gz` and `.xz` files. Install brotli on WSL Ubuntu and use that to extract the `.br` file.

We are given a memory dump, which indicates using a specialty tool, such as the open-source [volatility3](https://github.com/volatilityfoundation/volatility3) framework. This folder contains `pixi.toml` and `pixi.lock` files suitable for installing python3 tools using [pixi](https://pixi.prefix.dev/latest/) package manager. Run `pixi shell` to activate the environment and download the tools for the first time.

We need a symbol table to use volatility3 and this can be generated from the given system map and/or kernel image. To generate the symbol table, use [dwarf2json](https://github.com/volatilityfoundation/dwarf2json). Clone and build this tool using:
```
git clone https://github.com/volatilityfoundation/dwarf2json.git
cd dwarf2json
go build
```

Then generate the symbol map using `./dwarf2json linux --elf vmlinux --system-map system.map > symbols_dwarf2json.json`

Alternatively, I also used [btf2json](https://github.com/vobst/btf2json) with success after patching one line of the output compared to `dwarf2json`. This symbol table also allowed me to successfully run the volatility3 `linux.capabilities` tool, which failed with `dwarf2json`. This additional capability did not prove helpful, but was interesting nonetheless.

`vol -f .\memory.dump --symbol-dirs=./symbols banners`

| Offset  |  Banner |
|:-------------:|:-------------------------:|
 |  0x4280af |   Linux version 5.15.134 (dsu@Ubuntu) (x86_64-openwrt-linux-musl-gcc (OpenWrt GCC 12.3.0 r23497-6637af95aa) 12.3.0, GNU ld (GNU Binutils) 2.40.0) #0 SMP Mon Oct 9 21:45:35 2023
 | 0x2000220 |   Linux version 5.15.134 (dsu@Ubuntu) (x86_64-openwrt-linux-musl-gcc (OpenWrt GCC 12.3.0 r23497-6637af95aa) 12.3.0, GNU ld (GNU Binutils) 2.40.0) #0 SMP Mon Oct 9 21:45:35 2023
 | 0x2d93258 | Linux version 5.15.134 (dsu@Ubuntu) (x86_64-openwrt-linux-musl-gcc (OpenWrt GCC 12.3.0 r23497-6637af95aa) 12.3.0, GNU ld (GNU Binutils) 2.40.0) #0 SMP Mon Oct 9 21:45:35 202323



`vol -f .\memory.dump --symbol-dirs=./symbols -r pretty linux.elfs`
```
  |  PID |  Process |          Start |            End |                        File Path | File Output
* |    1 |    procd | 0x562488818000 | 0x56248881e000 |                      /sbin/procd |    Disabled
* |    1 |    procd | 0x7f8389b85000 | 0x7f8389b89000 |               /lib/libgcc_s.so.1 |    Disabled
* |    1 |    procd | 0x7f8389b9d000 | 0x7f8389b9e000 |  /lib/libjson_script.so.20230523 |    Disabled
* |    1 |    procd | 0x7f8389ba2000 | 0x7f8389ba3000 | /lib/libblobmsg_json.so.20230523 |    Disabled
* |    1 |    procd | 0x7f8389ba7000 | 0x7f8389bab000 |      /usr/lib/libjson-c.so.5.2.0 |    Disabled
* |    1 |    procd | 0x7f8389bb8000 | 0x7f8389bba000 |         /lib/libubus.so.20230605 |    Disabled
* |    1 |    procd | 0x7f8389bc1000 | 0x7f8389bc4000 |         /lib/libubox.so.20230523 |    Disabled
* |    1 |    procd | 0x7f8389bce000 | 0x7f8389be2000 |                     /lib/libc.so |    Disabled
* |    1 |    procd | 0x7ffc04dbe000 | 0x7ffc04dbf000 |                           [vdso] |    Disabled
* |  514 |    ubusd | 0x5612db934000 | 0x5612db936000 |                      /sbin/ubusd |    Disabled
* |  514 |    ubusd | 0x7fc2d9baa000 | 0x7fc2d9bae000 |               /lib/libgcc_s.so.1 |    Disabled
* |  514 |    ubusd | 0x7fc2d9bc2000 | 0x7fc2d9bc6000 |      /usr/lib/libjson-c.so.5.2.0 |    Disabled
* |  514 |    ubusd | 0x7fc2d9bd3000 | 0x7fc2d9bd4000 | /lib/libblobmsg_json.so.20230523 |    Disabled
* |  514 |    ubusd | 0x7fc2d9bd8000 | 0x7fc2d9bdb000 |         /lib/libubox.so.20230523 |    Disabled
* |  514 |    ubusd | 0x7fc2d9be5000 | 0x7fc2d9bf9000 |                     /lib/libc.so |    Disabled
* |  514 |    ubusd | 0x7ffc03fa3000 | 0x7ffc03fa4000 |                           [vdso] |    Disabled
* |  515 |      ash |       0x400000 |       0x406000 |                     /bin/busybox |    Disabled
* |  515 |      ash | 0x7efd65a34000 | 0x7efd65a38000 |               /lib/libgcc_s.so.1 |    Disabled
* |  515 |      ash | 0x7efd65a4c000 | 0x7efd65a60000 |                     /lib/libc.so |    Disabled
* |  515 |      ash | 0x7fff87fe3000 | 0x7fff87fe4000 |                           [vdso] |    Disabled
* |  516 | askfirst | 0x55cd2b786000 | 0x55cd2b787000 |                   /sbin/askfirst |    Disabled
* |  516 | askfirst | 0x7fad015fb000 | 0x7fad015ff000 |               /lib/libgcc_s.so.1 |    Disabled
* |  516 | askfirst | 0x7fad01613000 | 0x7fad01627000 |                     /lib/libc.so |    Disabled
* |  516 | askfirst | 0x7ffdb9b91000 | 0x7ffdb9b92000 |                           [vdso] |    Disabled
* |  551 |    urngd |       0x400000 |       0x401000 |                      /sbin/urngd |    Disabled
* |  551 |    urngd | 0x7f9c0a0fd000 | 0x7f9c0a101000 |               /lib/libgcc_s.so.1 |    Disabled
* |  551 |    urngd | 0x7f9c0a115000 | 0x7f9c0a118000 |         /lib/libubox.so.20230523 |    Disabled
* |  551 |    urngd | 0x7f9c0a122000 | 0x7f9c0a136000 |                     /lib/libc.so |    Disabled
* |  551 |    urngd | 0x7ffff8189000 | 0x7ffff818a000 |                           [vdso] |    Disabled
* | 1018 |     logd |       0x400000 |       0x402000 |                       /sbin/logd |    Disabled
* | 1018 |     logd | 0x7f34ca2b0000 | 0x7f34ca2b4000 |               /lib/libgcc_s.so.1 |    Disabled
* | 1018 |     logd | 0x7f34ca2c8000 | 0x7f34ca2ca000 |         /lib/libubus.so.20230605 |    Disabled
* | 1018 |     logd | 0x7f34ca2d1000 | 0x7f34ca2d4000 |         /lib/libubox.so.20230523 |    Disabled
* | 1018 |     logd | 0x7f34ca2de000 | 0x7f34ca2f2000 |                     /lib/libc.so |    Disabled
* | 1018 |     logd | 0x7fff0430c000 | 0x7fff0430d000 |                           [vdso] |    Disabled
* | 1168 |  dnsmasq | 0x563a8f2f8000 | 0x563a8f2ff000 |                      /sbin/ujail |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad828000 | 0x7fc9ad82c000 |      /usr/lib/libjson-c.so.5.2.0 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad839000 | 0x7fc9ad83d000 |               /lib/libgcc_s.so.1 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad851000 | 0x7fc9ad852000 | /lib/libblobmsg_json.so.20230523 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad856000 | 0x7fc9ad858000 |                   /lib/libuci.so |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad862000 | 0x7fc9ad864000 |         /lib/libubus.so.20230605 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad86b000 | 0x7fc9ad86e000 |         /lib/libubox.so.20230523 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad878000 | 0x7fc9ad88c000 |                     /lib/libc.so |    Disabled
* | 1168 |  dnsmasq | 0x7ffc51596000 | 0x7ffc51597000 |                           [vdso] |    Disabled
* | 1174 |  dnsmasq | 0x558730c12000 | 0x558730c1a000 |                /usr/sbin/dnsmasq |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a33000 | 0x7f13d3a37000 |               /lib/libgcc_s.so.1 |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a4b000 | 0x7f13d3a4d000 |         /lib/libubus.so.20230605 |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a54000 | 0x7f13d3a57000 |         /lib/libubox.so.20230523 |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a61000 | 0x7f13d3a75000 |         /lib/ld-musl-x86_64.so.1 |    Disabled
* | 1174 |  dnsmasq | 0x7ffea3ac2000 | 0x7ffea3ac3000 |                           [vdso] |    Disabled
* | 1244 | dropbear | 0x55c4d6771000 | 0x55c4d6775000 |               /usr/sbin/dropbear |    Disabled
* | 1244 | dropbear | 0x7fe0e9f16000 | 0x7fe0e9f1a000 |               /lib/libgcc_s.so.1 |    Disabled
* | 1244 | dropbear | 0x7fe0e9f2e000 | 0x7fe0e9f42000 |                     /lib/libc.so |    Disabled
* | 1244 | dropbear | 0x7ffc2db46000 | 0x7ffc2db47000 |                           [vdso] |    Disabled
* | 1405 |   netifd |       0x400000 |       0x404000 |                     /sbin/netifd |    Disabled
* | 1405 |   netifd | 0x7f3d3b3ee000 | 0x7f3d3b3f2000 |               /lib/libgcc_s.so.1 |    Disabled
* | 1405 |   netifd | 0x7f3d3b406000 | 0x7f3d3b409000 |         /usr/lib/libnl-tiny.so.1 |    Disabled
* | 1405 |   netifd | 0x7f3d3b410000 | 0x7f3d3b411000 | /lib/libblobmsg_json.so.20230523 |    Disabled
* | 1405 |   netifd | 0x7f3d3b415000 | 0x7f3d3b419000 |      /usr/lib/libjson-c.so.5.2.0 |    Disabled
* | 1405 |   netifd | 0x7f3d3b426000 | 0x7f3d3b428000 |                   /lib/libuci.so |    Disabled
* | 1405 |   netifd | 0x7f3d3b432000 | 0x7f3d3b434000 |         /lib/libubus.so.20230605 |    Disabled
* | 1405 |   netifd | 0x7f3d3b43b000 | 0x7f3d3b43e000 |         /lib/libubox.so.20230523 |    Disabled
* | 1405 |   netifd | 0x7f3d3b448000 | 0x7f3d3b45c000 |                     /lib/libc.so |    Disabled
* | 1405 |   netifd | 0x7ffdded45000 | 0x7ffdded46000 |                           [vdso] |    Disabled
* | 1524 |   odhcpd | 0x558033ac3000 | 0x558033ac7000 |                 /usr/sbin/odhcpd |    Disabled
* | 1524 |   odhcpd | 0x7fe9f686a000 | 0x7fe9f686e000 |               /lib/libgcc_s.so.1 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f6882000 | 0x7fe9f6884000 |         /lib/libubus.so.20230605 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f688b000 | 0x7fe9f688e000 |         /usr/lib/libnl-tiny.so.1 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f6895000 | 0x7fe9f6897000 |                   /lib/libuci.so |    Disabled
* | 1524 |   odhcpd | 0x7fe9f68a1000 | 0x7fe9f68a4000 |         /lib/libubox.so.20230523 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f68ae000 | 0x7fe9f68c2000 |                     /lib/libc.so |    Disabled
* | 1524 |   odhcpd | 0x7fff1945a000 | 0x7fff1945b000 |                           [vdso] |    Disabled
* | 1552 |        4 | 0x564595660000 | 0x564595661000 |               /memfd:x (deleted) |    Disabled
* | 1552 |        4 | 0x7f3b2d6ed000 | 0x7f3b2d701000 |                     /lib/libc.so |    Disabled
* | 1552 |        4 | 0x7fffbdf79000 | 0x7fffbdf7a000 |                           [vdso] |    Disabled
* | 1744 |     ntpd | 0x55f9df386000 | 0x55f9df38d000 |                      /sbin/ujail |    Disabled
* | 1744 |     ntpd | 0x7fa31d047000 | 0x7fa31d04b000 |      /usr/lib/libjson-c.so.5.2.0 |    Disabled
* | 1744 |     ntpd | 0x7fa31d058000 | 0x7fa31d05c000 |               /lib/libgcc_s.so.1 |    Disabled
* | 1744 |     ntpd | 0x7fa31d070000 | 0x7fa31d071000 | /lib/libblobmsg_json.so.20230523 |    Disabled
* | 1744 |     ntpd | 0x7fa31d075000 | 0x7fa31d077000 |                   /lib/libuci.so |    Disabled
* | 1744 |     ntpd | 0x7fa31d081000 | 0x7fa31d083000 |         /lib/libubus.so.20230605 |    Disabled
* | 1744 |     ntpd | 0x7fa31d08a000 | 0x7fa31d08d000 |         /lib/libubox.so.20230523 |    Disabled
* | 1744 |     ntpd | 0x7fa31d097000 | 0x7fa31d0ab000 |                     /lib/libc.so |    Disabled
* | 1744 |     ntpd | 0x7ffebebae000 | 0x7ffebebaf000 |                           [vdso] |    Disabled
* | 1749 |     ntpd |       0x400000 |       0x406000 |                   /usr/sbin/ntpd |    Disabled
* | 1749 |     ntpd | 0x7fceb6ef0000 | 0x7fceb6ef4000 |               /lib/libgcc_s.so.1 |    Disabled
* | 1749 |     ntpd | 0x7fceb6f08000 | 0x7fceb6f1c000 |         /lib/ld-musl-x86_64.so.1 |    Disabled
* | 1749 |     ntpd | 0x7ffca2bdf000 | 0x7ffca2be0000 |                           [vdso] |    Disabled
* | 1854 |  service |       0x400000 |       0x406000 |                     /bin/busybox |    Disabled
* | 1854 |  service | 0x7fec32260000 | 0x7fec32264000 |               /lib/libgcc_s.so.1 |    Disabled
* | 1854 |  service | 0x7fec32278000 | 0x7fec3228c000 |                     /lib/libc.so |    Disabled
* | 1854 |  service | 0x7ffc2bfb3000 | 0x7ffc2bfb4000 |                           [vdso] |    Disabled
* | 1855 |  dnsmasq |       0x400000 |       0x406000 |                     /bin/busybox |    Disabled
* | 1855 |  dnsmasq | 0x7f275f5b4000 | 0x7f275f5b8000 |               /lib/libgcc_s.so.1 |    Disabled
* | 1855 |  dnsmasq | 0x7f275f5cc000 | 0x7f275f5e0000 |                     /lib/libc.so |    Disabled
* | 1855 |  dnsmasq | 0x7ffcfdaf5000 | 0x7ffcfdaf6000 |                           [vdso] |    Disabled
```

`vol -f .\memory.dump --symbol-dirs=./symbols -r pretty linux.lsof`
```
  |  PID |  TID |  Process | FD |                      Path | Device |      Inode | Type |       Mode |                        Changed |                       Modified |                       Accessed |   Size
* |    1 |    1 |    procd |  0 |              /dev/console |   0:19 |         36 |  CHR | crw------- | 2025-09-06 04:53:42.140000 UTC | 2025-09-06 04:53:42.140000 UTC | 2025-09-06 04:53:42.140000 UTC |      0
* |    1 |    1 |    procd |  1 |              /dev/console |   0:19 |         36 |  CHR | crw------- | 2025-09-06 04:53:42.140000 UTC | 2025-09-06 04:53:42.140000 UTC | 2025-09-06 04:53:42.140000 UTC |      0
* |    1 |    1 |    procd |  2 |              /dev/console |   0:19 |         36 |  CHR | crw------- | 2025-09-06 04:53:42.140000 UTC | 2025-09-06 04:53:42.140000 UTC | 2025-09-06 04:53:42.140000 UTC |      0
* |    1 |    1 |    procd |  3 |         anon_inode:[6519] |   0:11 |       6519 |    - | ?rw------- | 2025-09-06 04:53:34.720000 UTC | 2025-09-06 04:53:34.720000 UTC | 2025-09-06 04:53:34.720000 UTC |      0
* |    1 |    1 |    procd |  4 |                pipe:[118] |   0:10 |        118 | FIFO | prw------- | 2025-09-06 04:54:13.710000 UTC | 2025-09-06 04:54:13.710000 UTC | 2025-09-06 04:54:13.710000 UTC |      0
* |    1 |    1 |    procd |  5 |                pipe:[118] |   0:10 |        118 | FIFO | prw------- | 2025-09-06 04:54:13.710000 UTC | 2025-09-06 04:54:13.710000 UTC | 2025-09-06 04:54:13.710000 UTC |      0
* |    1 |    1 |    procd |  6 |              socket:[119] |    0:6 |        119 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* |    1 |    1 |    procd |  7 |             socket:[7243] |    0:6 |       7243 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* |    1 |    1 |    procd |  8 |         anon_inode:[6519] |   0:11 |       6519 |    - | ?rw------- | 2025-09-06 04:53:34.720000 UTC | 2025-09-06 04:53:34.720000 UTC | 2025-09-06 04:53:34.720000 UTC |      0
* |    1 |    1 |    procd | 12 |                pipe:[800] |   0:10 |        800 | FIFO | prw------- | 2025-09-06 04:54:13.510000 UTC | 2025-09-06 04:54:13.510000 UTC | 2025-09-06 04:54:13.510000 UTC |      0
* |    1 |    1 |    procd | 14 |                pipe:[801] |   0:10 |        801 | FIFO | prw------- | 2025-09-06 04:54:13.210000 UTC | 2025-09-06 04:54:13.210000 UTC | 2025-09-06 04:54:13.210000 UTC |      0
* |  514 |  514 |    ubusd |  0 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* |  514 |  514 |    ubusd |  1 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* |  514 |  514 |    ubusd |  2 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* |  514 |  514 |    ubusd |  3 |              /dev/urandom |   0:19 |         13 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* |  514 |  514 |    ubusd |  4 |         anon_inode:[6519] |   0:11 |       6519 |    - | ?rw------- | 2025-09-06 04:53:34.720000 UTC | 2025-09-06 04:53:34.720000 UTC | 2025-09-06 04:53:34.720000 UTC |      0
* |  514 |  514 |    ubusd |  5 |                pipe:[121] |   0:10 |        121 | FIFO | prw------- | 2025-09-06 04:53:42.840000 UTC | 2025-09-06 04:53:42.840000 UTC | 2025-09-06 04:53:42.840000 UTC |      0
* |  514 |  514 |    ubusd |  6 |                pipe:[121] |   0:10 |        121 | FIFO | prw------- | 2025-09-06 04:53:42.840000 UTC | 2025-09-06 04:53:42.840000 UTC | 2025-09-06 04:53:42.840000 UTC |      0
* |  514 |  514 |    ubusd |  7 |              socket:[122] |    0:6 |        122 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* |  514 |  514 |    ubusd |  8 |              socket:[123] |    0:6 |        123 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* |  514 |  514 |    ubusd |  9 |              socket:[124] |    0:6 |        124 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* |  514 |  514 |    ubusd | 10 |             socket:[9351] |    0:6 |       9351 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* |  514 |  514 |    ubusd | 11 |              socket:[412] |    0:6 |        412 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* |  514 |  514 |    ubusd | 12 |              socket:[421] |    0:6 |        421 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* |  514 |  514 |    ubusd | 13 |              socket:[534] |    0:6 |        534 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* |  514 |  514 |    ubusd | 14 |              socket:[621] |    0:6 |        621 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* |  514 |  514 |    ubusd | 15 |              socket:[778] |    0:6 |        778 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* |  515 |  515 |      ash |  0 |                /dev/ttyS0 |   0:19 |         52 |  CHR | crw-rw---- | 2025-09-06 04:53:42.190000 UTC | 2025-09-06 04:54:16.190000 UTC | 2025-09-06 04:54:10.190000 UTC |      0
* |  515 |  515 |      ash |  1 |                /dev/ttyS0 |   0:19 |         52 |  CHR | crw-rw---- | 2025-09-06 04:53:42.190000 UTC | 2025-09-06 04:54:16.190000 UTC | 2025-09-06 04:54:10.190000 UTC |      0
* |  515 |  515 |      ash |  2 |                /dev/ttyS0 |   0:19 |         52 |  CHR | crw-rw---- | 2025-09-06 04:53:42.190000 UTC | 2025-09-06 04:54:16.190000 UTC | 2025-09-06 04:54:10.190000 UTC |      0
* |  515 |  515 |      ash | 10 |                  /dev/tty |   0:19 |         80 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.230000 UTC | 2025-09-06 04:53:42.230000 UTC | 2025-09-06 04:53:42.230000 UTC |      0
* |  515 |  515 |      ash | 11 |                /dev/ttyS0 |   0:19 |         52 |  CHR | crw-rw---- | 2025-09-06 04:53:42.190000 UTC | 2025-09-06 04:54:16.190000 UTC | 2025-09-06 04:54:10.190000 UTC |      0
* |  516 |  516 | askfirst |  0 |                 /dev/tty1 |   0:19 |         29 |  CHR | crw-rw---- | 2025-09-06 04:53:42.110000 UTC | 2025-09-06 04:53:42.110000 UTC | 2025-09-06 04:53:42.110000 UTC |      0
* |  516 |  516 | askfirst |  1 |                 /dev/tty1 |   0:19 |         29 |  CHR | crw-rw---- | 2025-09-06 04:53:42.110000 UTC | 2025-09-06 04:53:42.110000 UTC | 2025-09-06 04:53:42.110000 UTC |      0
* |  516 |  516 | askfirst |  2 |                 /dev/tty1 |   0:19 |         29 |  CHR | crw-rw---- | 2025-09-06 04:53:42.110000 UTC | 2025-09-06 04:53:42.110000 UTC | 2025-09-06 04:53:42.110000 UTC |      0
* |  551 |  551 |    urngd |  0 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* |  551 |  551 |    urngd |  1 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* |  551 |  551 |    urngd |  2 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* |  551 |  551 |    urngd |  3 |         anon_inode:[6519] |   0:11 |       6519 |    - | ?rw------- | 2025-09-06 04:53:34.720000 UTC | 2025-09-06 04:53:34.720000 UTC | 2025-09-06 04:53:34.720000 UTC |      0
* |  551 |  551 |    urngd |  4 |               pipe:[7266] |   0:10 |       7266 | FIFO | prw------- | 2025-09-06 04:53:43.720000 UTC | 2025-09-06 04:53:43.720000 UTC | 2025-09-06 04:53:43.720000 UTC |      0
* |  551 |  551 |    urngd |  5 |               pipe:[7266] |   0:10 |       7266 | FIFO | prw------- | 2025-09-06 04:53:43.720000 UTC | 2025-09-06 04:53:43.720000 UTC | 2025-09-06 04:53:43.720000 UTC |      0
* |  551 |  551 |    urngd |  6 |               /dev/random |   0:19 |         10 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* | 1018 | 1018 |     logd |  0 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* | 1018 | 1018 |     logd |  1 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* | 1018 | 1018 |     logd |  2 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* | 1018 | 1018 |     logd |  3 |         anon_inode:[6519] |   0:11 |       6519 |    - | ?rw------- | 2025-09-06 04:53:34.720000 UTC | 2025-09-06 04:53:34.720000 UTC | 2025-09-06 04:53:34.720000 UTC |      0
* | 1018 | 1018 |     logd |  4 |               pipe:[9347] |   0:10 |       9347 | FIFO | prw------- | 2025-09-06 04:53:53.680000 UTC | 2025-09-06 04:53:53.680000 UTC | 2025-09-06 04:53:53.680000 UTC |      0
* | 1018 | 1018 |     logd |  5 |               pipe:[9347] |   0:10 |       9347 | FIFO | prw------- | 2025-09-06 04:53:53.680000 UTC | 2025-09-06 04:53:53.680000 UTC | 2025-09-06 04:53:53.680000 UTC |      0
* | 1018 | 1018 |     logd |  6 |             socket:[9348] |    0:6 |       9348 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1018 | 1018 |     logd |  7 |                /proc/kmsg |   0:15 | 4026532026 |  REG | -r-------- | 2025-09-06 04:53:53.720000 UTC | 2025-09-06 04:53:53.720000 UTC | 2025-09-06 04:53:53.720000 UTC |      0
* | 1018 | 1018 |     logd |  8 |             socket:[9350] |    0:6 |       9350 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1168 | 1168 |  dnsmasq |  0 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* | 1168 | 1168 |  dnsmasq |  1 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* | 1168 | 1168 |  dnsmasq |  2 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* | 1168 | 1168 |  dnsmasq |  3 |         anon_inode:[6519] |   0:11 |       6519 |    - | ?rw------- | 2025-09-06 04:53:34.720000 UTC | 2025-09-06 04:53:34.720000 UTC | 2025-09-06 04:53:34.720000 UTC |      0
* | 1168 | 1168 |  dnsmasq |  4 |               pipe:[9794] |   0:10 |       9794 | FIFO | prw------- | 2025-09-06 04:53:55.980000 UTC | 2025-09-06 04:53:55.980000 UTC | 2025-09-06 04:53:55.980000 UTC |      0
* | 1168 | 1168 |  dnsmasq |  5 |               pipe:[9794] |   0:10 |       9794 | FIFO | prw------- | 2025-09-06 04:53:55.980000 UTC | 2025-09-06 04:53:55.980000 UTC | 2025-09-06 04:53:55.980000 UTC |      0
* | 1168 | 1168 |  dnsmasq |  6 |             socket:[9795] |    0:6 |       9795 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1174 | 1174 |  dnsmasq |  0 |                 /dev/null |   0:24 |          4 |  CHR | crw-rw-rw- | 2025-09-06 04:53:56.030000 UTC | 2025-09-06 04:53:56.030000 UTC | 2025-09-06 04:53:56.030000 UTC |      0
* | 1174 | 1174 |  dnsmasq |  1 |                 /dev/null |   0:24 |          4 |  CHR | crw-rw-rw- | 2025-09-06 04:53:56.030000 UTC | 2025-09-06 04:53:56.030000 UTC | 2025-09-06 04:53:56.030000 UTC |      0
* | 1174 | 1174 |  dnsmasq |  2 |                 /dev/null |   0:24 |          4 |  CHR | crw-rw-rw- | 2025-09-06 04:53:56.030000 UTC | 2025-09-06 04:53:56.030000 UTC | 2025-09-06 04:53:56.030000 UTC |      0
* | 1174 | 1174 |  dnsmasq |  3 |              socket:[417] |    0:6 |        417 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1174 | 1174 |  dnsmasq |  4 |         anon_inode:[6519] |   0:11 |       6519 |    - | ?rw------- | 2025-09-06 04:53:34.720000 UTC | 2025-09-06 04:53:34.720000 UTC | 2025-09-06 04:53:34.720000 UTC |      0
* | 1174 | 1174 |  dnsmasq |  5 |         anon_inode:[6519] |   0:11 |       6519 |    - | ?rw------- | 2025-09-06 04:53:34.720000 UTC | 2025-09-06 04:53:34.720000 UTC | 2025-09-06 04:53:34.720000 UTC |      0
* | 1174 | 1174 |  dnsmasq |  6 |                pipe:[419] |   0:10 |        419 | FIFO | prw------- | 2025-09-06 04:53:56.080000 UTC | 2025-09-06 04:53:56.080000 UTC | 2025-09-06 04:53:56.080000 UTC |      0
* | 1174 | 1174 |  dnsmasq |  7 |                pipe:[419] |   0:10 |        419 | FIFO | prw------- | 2025-09-06 04:53:56.080000 UTC | 2025-09-06 04:53:56.080000 UTC | 2025-09-06 04:53:56.080000 UTC |      0
* | 1174 | 1174 |  dnsmasq |  8 |              socket:[420] |    0:6 |        420 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1174 | 1174 |  dnsmasq |  9 |                pipe:[423] |   0:10 |        423 | FIFO | prw------- | 2025-09-06 04:54:11.640000 UTC | 2025-09-06 04:54:11.640000 UTC | 2025-09-06 04:54:11.640000 UTC |      0
* | 1174 | 1174 |  dnsmasq | 10 |                pipe:[423] |   0:10 |        423 | FIFO | prw------- | 2025-09-06 04:54:11.640000 UTC | 2025-09-06 04:54:11.640000 UTC | 2025-09-06 04:54:11.640000 UTC |      0
* | 1174 | 1174 |  dnsmasq | 11 |              socket:[424] |    0:6 |        424 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1174 | 1174 |  dnsmasq | 12 |              socket:[710] |    0:6 |        710 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1174 | 1174 |  dnsmasq | 13 |              socket:[711] |    0:6 |        711 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1174 | 1174 |  dnsmasq | 14 |              socket:[712] |    0:6 |        712 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1174 | 1174 |  dnsmasq | 15 |              socket:[713] |    0:6 |        713 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1244 | 1244 | dropbear |  0 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* | 1244 | 1244 | dropbear |  1 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* | 1244 | 1244 | dropbear |  2 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* | 1244 | 1244 | dropbear |  3 |              socket:[450] |    0:6 |        450 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1244 | 1244 | dropbear |  4 |              socket:[451] |    0:6 |        451 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1244 | 1244 | dropbear |  5 |        /usr/sbin/dropbear |  254:0 |       1334 |  REG | -rwxr-xr-x | 2023-10-09 21:45:35.000000 UTC | 2023-10-09 21:45:35.000000 UTC | 2023-10-09 21:45:35.000000 UTC | 205787
* | 1244 | 1244 | dropbear |  6 |              socket:[452] |    0:6 |        452 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1405 | 1405 |   netifd |  0 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* | 1405 | 1405 |   netifd |  1 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* | 1405 | 1405 |   netifd |  2 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* | 1405 | 1405 |   netifd |  3 |              socket:[531] |    0:6 |        531 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1405 | 1405 |   netifd |  4 |         anon_inode:[6519] |   0:11 |       6519 |    - | ?rw------- | 2025-09-06 04:53:34.720000 UTC | 2025-09-06 04:53:34.720000 UTC | 2025-09-06 04:53:34.720000 UTC |      0
* | 1405 | 1405 |   netifd |  5 |                pipe:[532] |   0:10 |        532 | FIFO | prw------- | 2025-09-06 04:54:12.890000 UTC | 2025-09-06 04:54:12.890000 UTC | 2025-09-06 04:54:12.890000 UTC |      0
* | 1405 | 1405 |   netifd |  6 |                pipe:[532] |   0:10 |        532 | FIFO | prw------- | 2025-09-06 04:54:12.890000 UTC | 2025-09-06 04:54:12.890000 UTC | 2025-09-06 04:54:12.890000 UTC |      0
* | 1405 | 1405 |   netifd |  7 |              socket:[533] |    0:6 |        533 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1405 | 1405 |   netifd |  8 |            socket:[10052] |    0:6 |      10052 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1405 | 1405 |   netifd |  9 |         /lib/netifd/proto |  254:0 |        489 |  DIR | drwxr-xr-x | 2023-10-09 21:45:35.000000 UTC | 2023-10-09 21:45:35.000000 UTC | 2023-10-09 21:45:35.000000 UTC |   4096
* | 1405 | 1405 |   netifd | 10 |      /lib/netifd/wireless |  254:0 |        494 |  DIR | drwxr-xr-x | 2023-10-09 21:45:35.000000 UTC | 2023-10-09 21:45:35.000000 UTC | 2023-10-09 21:45:35.000000 UTC |   4096
* | 1405 | 1405 |   netifd | 11 |            socket:[10053] |    0:6 |      10053 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1405 | 1405 |   netifd | 12 |            socket:[10054] |    0:6 |      10054 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1405 | 1405 |   netifd | 13 |            socket:[10055] |    0:6 |      10055 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1524 | 1524 |   odhcpd |  0 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* | 1524 | 1524 |   odhcpd |  1 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* | 1524 | 1524 |   odhcpd |  2 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* | 1524 | 1524 |   odhcpd |  3 |         anon_inode:[6519] |   0:11 |       6519 |    - | ?rw------- | 2025-09-06 04:53:34.720000 UTC | 2025-09-06 04:53:34.720000 UTC | 2025-09-06 04:53:34.720000 UTC |      0
* | 1524 | 1524 |   odhcpd |  4 |                pipe:[612] |   0:10 |        612 | FIFO | prw------- | 2025-09-06 04:54:09.840000 UTC | 2025-09-06 04:54:09.840000 UTC | 2025-09-06 04:54:09.840000 UTC |      0
* | 1524 | 1524 |   odhcpd |  5 |                pipe:[612] |   0:10 |        612 | FIFO | prw------- | 2025-09-06 04:54:09.840000 UTC | 2025-09-06 04:54:09.840000 UTC | 2025-09-06 04:54:09.840000 UTC |      0
* | 1524 | 1524 |   odhcpd |  6 |              socket:[613] |    0:6 |        613 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1524 | 1524 |   odhcpd |  7 |              /dev/urandom |   0:19 |         13 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* | 1524 | 1524 |   odhcpd |  8 |              socket:[614] |    0:6 |        614 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1524 | 1524 |   odhcpd |  9 |              socket:[615] |    0:6 |        615 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1524 | 1524 |   odhcpd | 10 | /proc/1524/net/ipv6_route |   0:15 | 4026532141 |  REG | -r--r--r-- | 2025-09-06 04:54:09.840000 UTC | 2025-09-06 04:54:09.840000 UTC | 2025-09-06 04:54:09.840000 UTC |      0
* | 1524 | 1524 |   odhcpd | 11 |                pipe:[619] |   0:10 |        619 | FIFO | prw------- | 2025-09-06 04:54:09.840000 UTC | 2025-09-06 04:54:09.840000 UTC | 2025-09-06 04:54:09.840000 UTC |      0
* | 1524 | 1524 |   odhcpd | 12 |                pipe:[619] |   0:10 |        619 | FIFO | prw------- | 2025-09-06 04:54:09.840000 UTC | 2025-09-06 04:54:09.840000 UTC | 2025-09-06 04:54:09.840000 UTC |      0
* | 1524 | 1524 |   odhcpd | 13 |              socket:[620] |    0:6 |        620 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1552 | 1552 |        4 |  0 |                /dev/ttyS0 |   0:19 |         52 |  CHR | crw-rw---- | 2025-09-06 04:53:42.190000 UTC | 2025-09-06 04:54:16.190000 UTC | 2025-09-06 04:54:10.190000 UTC |      0
* | 1552 | 1552 |        4 |  1 |                /dev/ttyS0 |   0:19 |         52 |  CHR | crw-rw---- | 2025-09-06 04:53:42.190000 UTC | 2025-09-06 04:54:16.190000 UTC | 2025-09-06 04:54:10.190000 UTC |      0
* | 1552 | 1552 |        4 |  2 |                /dev/ttyS0 |   0:19 |         52 |  CHR | crw-rw---- | 2025-09-06 04:53:42.190000 UTC | 2025-09-06 04:54:16.190000 UTC | 2025-09-06 04:54:10.190000 UTC |      0
* | 1552 | 1552 |        4 |  5 |        /memfd:c (deleted) |    0:1 |          4 |  REG | -r--r--r-- | 2025-09-06 04:54:16.160000 UTC | 2025-09-06 04:54:16.140000 UTC | 2025-09-06 04:54:16.460000 UTC |   1632
* | 1744 | 1744 |     ntpd |  0 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* | 1744 | 1744 |     ntpd |  1 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* | 1744 | 1744 |     ntpd |  2 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* | 1744 | 1744 |     ntpd |  3 |         anon_inode:[6519] |   0:11 |       6519 |    - | ?rw------- | 2025-09-06 04:53:34.720000 UTC | 2025-09-06 04:53:34.720000 UTC | 2025-09-06 04:53:34.720000 UTC |      0
* | 1744 | 1744 |     ntpd |  4 |                pipe:[775] |   0:10 |        775 | FIFO | prw------- | 2025-09-06 04:54:12.640000 UTC | 2025-09-06 04:54:12.640000 UTC | 2025-09-06 04:54:12.640000 UTC |      0
* | 1744 | 1744 |     ntpd |  5 |                pipe:[775] |   0:10 |        775 | FIFO | prw------- | 2025-09-06 04:54:12.640000 UTC | 2025-09-06 04:54:12.640000 UTC | 2025-09-06 04:54:12.640000 UTC |      0
* | 1744 | 1744 |     ntpd |  6 |              socket:[777] |    0:6 |        777 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1749 | 1749 |     ntpd |  0 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* | 1749 | 1749 |     ntpd |  1 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* | 1749 | 1749 |     ntpd |  2 |                 /dev/null |   0:19 |         16 |  CHR | crw-rw-rw- | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC | 2025-09-06 04:53:42.040000 UTC |      0
* | 1749 | 1749 |     ntpd |  3 |              socket:[784] |    0:6 |        784 | SOCK | srwxrwxrwx |                              - |                              - |                              - |      0
* | 1854 | 1854 |  service |  0 |                /dev/ttyS0 |   0:19 |         52 |  CHR | crw-rw---- | 2025-09-06 04:53:42.190000 UTC | 2025-09-06 04:54:16.190000 UTC | 2025-09-06 04:54:10.190000 UTC |      0
* | 1854 | 1854 |  service |  1 |                /dev/ttyS0 |   0:19 |         52 |  CHR | crw-rw---- | 2025-09-06 04:53:42.190000 UTC | 2025-09-06 04:54:16.190000 UTC | 2025-09-06 04:54:10.190000 UTC |      0
* | 1854 | 1854 |  service |  2 |                /dev/ttyS0 |   0:19 |         52 |  CHR | crw-rw---- | 2025-09-06 04:53:42.190000 UTC | 2025-09-06 04:54:16.190000 UTC | 2025-09-06 04:54:10.190000 UTC |      0
* | 1854 | 1854 |  service |  5 |        /memfd:c (deleted) |    0:1 |          4 |  REG | -r--r--r-- | 2025-09-06 04:54:16.160000 UTC | 2025-09-06 04:54:16.140000 UTC | 2025-09-06 04:54:16.460000 UTC |   1632
* | 1854 | 1854 |  service | 10 |             /sbin/service |  254:0 |        581 |  REG | -rwxr-xr-x | 2023-10-09 21:45:35.000000 UTC | 2023-10-09 21:45:35.000000 UTC | 2023-10-09 21:45:35.000000 UTC |    716
* | 1855 | 1855 |  dnsmasq |  0 |                /dev/ttyS0 |   0:19 |         52 |  CHR | crw-rw---- | 2025-09-06 04:53:42.190000 UTC | 2025-09-06 04:54:16.190000 UTC | 2025-09-06 04:54:10.190000 UTC |      0
* | 1855 | 1855 |  dnsmasq |  1 |                /dev/ttyS0 |   0:19 |         52 |  CHR | crw-rw---- | 2025-09-06 04:53:42.190000 UTC | 2025-09-06 04:54:16.190000 UTC | 2025-09-06 04:54:10.190000 UTC |      0
* | 1855 | 1855 |  dnsmasq |  2 |                /dev/ttyS0 |   0:19 |         52 |  CHR | crw-rw---- | 2025-09-06 04:53:42.190000 UTC | 2025-09-06 04:54:16.190000 UTC | 2025-09-06 04:54:10.190000 UTC |      0
* | 1855 | 1855 |  dnsmasq |  5 |        /memfd:c (deleted) |    0:1 |          4 |  REG | -r--r--r-- | 2025-09-06 04:54:16.160000 UTC | 2025-09-06 04:54:16.140000 UTC | 2025-09-06 04:54:16.460000 UTC |   1632
```

`vol -f .\memory.dump --symbol-dirs=./symbols -r pretty linux.pidhashtable`
```
  |         OFFSET |  PID |  TID | PPID |            COMM
* | 0x88800631da40 | 1018 | 1018 |    1 |            logd
* | 0x8880067f9e40 | 1168 | 1168 |    1 |         dnsmasq
* | 0x8880067f8040 | 1174 | 1174 | 1168 |         dnsmasq
* | 0x8880063c1e40 | 1244 | 1244 |    1 |        dropbear
* | 0x888003f20040 | 1405 | 1405 |    1 |          netifd
* | 0x88800631ad40 | 1524 | 1524 |    1 |          odhcpd
* | 0x888003edad40 | 1552 | 1552 |  515 |               4
* | 0x8880067f8f40 | 1744 | 1744 |    1 |            ntpd
* | 0x8880057acb40 | 1749 | 1749 | 1744 |            ntpd
* | 0x8880063c0040 | 1854 | 1854 | 1552 |         service
* | 0x8880063c2d40 | 1855 | 1855 | 1854 |         dnsmasq
```

`vol -f .\memory.dump --symbol-dirs=./symbols -r pretty linux.proc.Maps`
```
  |  PID |  Process |          Start |            End | Flags |   PgOff | Major | Minor | Inode |                        File Path | File output
* | 1018 |     logd |       0x400000 |       0x402000 |   r-- |     0x0 |   254 |     0 |   564 |                       /sbin/logd |    Disabled
* | 1018 |     logd |       0x402000 |       0x403000 |   r-x |  0x2000 |   254 |     0 |   564 |                       /sbin/logd |    Disabled
* | 1018 |     logd |       0x403000 |       0x404000 |   r-- |  0x3000 |   254 |     0 |   564 |                       /sbin/logd |    Disabled
* | 1018 |     logd |       0x404000 |       0x405000 |   r-- |  0x3000 |   254 |     0 |   564 |                       /sbin/logd |    Disabled
* | 1018 |     logd |       0x405000 |       0x406000 |   rw- |  0x4000 |   254 |     0 |   564 |                       /sbin/logd |    Disabled
* | 1018 |     logd |      0x1ff8000 |      0x1ff9000 |   --- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1018 |     logd |      0x1ff9000 |      0x1ffa000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1018 |     logd | 0x7f34ca28a000 | 0x7f34ca2b0000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1018 |     logd | 0x7f34ca2b0000 | 0x7f34ca2b4000 |   r-- |     0x0 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1018 |     logd | 0x7f34ca2b4000 | 0x7f34ca2c3000 |   r-x |  0x4000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1018 |     logd | 0x7f34ca2c3000 | 0x7f34ca2c6000 |   r-- | 0x13000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1018 |     logd | 0x7f34ca2c6000 | 0x7f34ca2c7000 |   r-- | 0x15000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1018 |     logd | 0x7f34ca2c7000 | 0x7f34ca2c8000 |   rw- | 0x16000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1018 |     logd | 0x7f34ca2c8000 | 0x7f34ca2ca000 |   r-- |     0x0 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1018 |     logd | 0x7f34ca2ca000 | 0x7f34ca2cd000 |   r-x |  0x2000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1018 |     logd | 0x7f34ca2cd000 | 0x7f34ca2cf000 |   r-- |  0x5000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1018 |     logd | 0x7f34ca2cf000 | 0x7f34ca2d0000 |   r-- |  0x6000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1018 |     logd | 0x7f34ca2d0000 | 0x7f34ca2d1000 |   rw- |  0x7000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1018 |     logd | 0x7f34ca2d1000 | 0x7f34ca2d4000 |   r-- |     0x0 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1018 |     logd | 0x7f34ca2d4000 | 0x7f34ca2d9000 |   r-x |  0x3000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1018 |     logd | 0x7f34ca2d9000 | 0x7f34ca2dc000 |   r-- |  0x8000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1018 |     logd | 0x7f34ca2dc000 | 0x7f34ca2dd000 |   r-- |  0xa000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1018 |     logd | 0x7f34ca2dd000 | 0x7f34ca2de000 |   rw- |  0xb000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1018 |     logd | 0x7f34ca2de000 | 0x7f34ca2f2000 |   r-- |     0x0 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1018 |     logd | 0x7f34ca2f2000 | 0x7f34ca33e000 |   r-x | 0x14000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1018 |     logd | 0x7f34ca33e000 | 0x7f34ca353000 |   r-- | 0x60000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1018 |     logd | 0x7f34ca353000 | 0x7f34ca354000 |   r-- | 0x74000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1018 |     logd | 0x7f34ca354000 | 0x7f34ca355000 |   rw- | 0x75000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1018 |     logd | 0x7f34ca355000 | 0x7f34ca358000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1018 |     logd | 0x7fff04233000 | 0x7fff04254000 |   rw- |     0x0 |     0 |     0 |     0 |                          [stack] |    Disabled
* | 1018 |     logd | 0x7fff04308000 | 0x7fff0430c000 |   r-- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1018 |     logd | 0x7fff0430c000 | 0x7fff0430d000 |   r-x |     0x0 |     0 |     0 |     0 |                           [vdso] |    Disabled
* | 1168 |  dnsmasq | 0x563a8f2f8000 | 0x563a8f2ff000 |   r-- |     0x0 |   254 |     0 |   592 |                      /sbin/ujail |    Disabled
* | 1168 |  dnsmasq | 0x563a8f2ff000 | 0x563a8f30b000 |   r-x |  0x7000 |   254 |     0 |   592 |                      /sbin/ujail |    Disabled
* | 1168 |  dnsmasq | 0x563a8f30b000 | 0x563a8f310000 |   r-- | 0x13000 |   254 |     0 |   592 |                      /sbin/ujail |    Disabled
* | 1168 |  dnsmasq | 0x563a8f310000 | 0x563a8f312000 |   r-- | 0x18000 |   254 |     0 |   592 |                      /sbin/ujail |    Disabled
* | 1168 |  dnsmasq | 0x563a8f312000 | 0x563a8f313000 |   rw- | 0x1a000 |   254 |     0 |   592 |                      /sbin/ujail |    Disabled
* | 1168 |  dnsmasq | 0x563a8f313000 | 0x563a8f415000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1168 |  dnsmasq | 0x563a91295000 | 0x563a91296000 |   --- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1168 |  dnsmasq | 0x563a91296000 | 0x563a91297000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad817000 | 0x7fc9ad828000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad828000 | 0x7fc9ad82c000 |   r-- |     0x0 |   254 |     0 |   727 |      /usr/lib/libjson-c.so.5.2.0 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad82c000 | 0x7fc9ad834000 |   r-x |  0x4000 |   254 |     0 |   727 |      /usr/lib/libjson-c.so.5.2.0 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad834000 | 0x7fc9ad837000 |   r-- |  0xc000 |   254 |     0 |   727 |      /usr/lib/libjson-c.so.5.2.0 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad837000 | 0x7fc9ad838000 |   r-- |  0xf000 |   254 |     0 |   727 |      /usr/lib/libjson-c.so.5.2.0 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad838000 | 0x7fc9ad839000 |   rw- | 0x10000 |   254 |     0 |   727 |      /usr/lib/libjson-c.so.5.2.0 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad839000 | 0x7fc9ad83d000 |   r-- |     0x0 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad83d000 | 0x7fc9ad84c000 |   r-x |  0x4000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad84c000 | 0x7fc9ad84f000 |   r-- | 0x13000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad84f000 | 0x7fc9ad850000 |   r-- | 0x15000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad850000 | 0x7fc9ad851000 |   rw- | 0x16000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad851000 | 0x7fc9ad852000 |   r-- |     0x0 |   254 |     0 |   360 | /lib/libblobmsg_json.so.20230523 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad852000 | 0x7fc9ad853000 |   r-x |  0x1000 |   254 |     0 |   360 | /lib/libblobmsg_json.so.20230523 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad853000 | 0x7fc9ad854000 |   r-- |  0x2000 |   254 |     0 |   360 | /lib/libblobmsg_json.so.20230523 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad854000 | 0x7fc9ad855000 |   r-- |  0x2000 |   254 |     0 |   360 | /lib/libblobmsg_json.so.20230523 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad855000 | 0x7fc9ad856000 |   rw- |  0x3000 |   254 |     0 |   360 | /lib/libblobmsg_json.so.20230523 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad856000 | 0x7fc9ad858000 |   r-- |     0x0 |   254 |     0 |   370 |                   /lib/libuci.so |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad858000 | 0x7fc9ad85e000 |   r-x |  0x2000 |   254 |     0 |   370 |                   /lib/libuci.so |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad85e000 | 0x7fc9ad860000 |   r-- |  0x8000 |   254 |     0 |   370 |                   /lib/libuci.so |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad860000 | 0x7fc9ad861000 |   r-- |  0x9000 |   254 |     0 |   370 |                   /lib/libuci.so |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad861000 | 0x7fc9ad862000 |   rw- |  0xa000 |   254 |     0 |   370 |                   /lib/libuci.so |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad862000 | 0x7fc9ad864000 |   r-- |     0x0 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad864000 | 0x7fc9ad867000 |   r-x |  0x2000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad867000 | 0x7fc9ad869000 |   r-- |  0x5000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad869000 | 0x7fc9ad86a000 |   r-- |  0x6000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad86a000 | 0x7fc9ad86b000 |   rw- |  0x7000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad86b000 | 0x7fc9ad86e000 |   r-- |     0x0 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad86e000 | 0x7fc9ad873000 |   r-x |  0x3000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad873000 | 0x7fc9ad876000 |   r-- |  0x8000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad876000 | 0x7fc9ad877000 |   r-- |  0xa000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad877000 | 0x7fc9ad878000 |   rw- |  0xb000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad878000 | 0x7fc9ad88c000 |   r-- |     0x0 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad88c000 | 0x7fc9ad8d8000 |   r-x | 0x14000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad8d8000 | 0x7fc9ad8ed000 |   r-- | 0x60000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad8ed000 | 0x7fc9ad8ee000 |   r-- | 0x74000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad8ee000 | 0x7fc9ad8ef000 |   rw- | 0x75000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1168 |  dnsmasq | 0x7fc9ad8ef000 | 0x7fc9ad8f2000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1168 |  dnsmasq | 0x7ffc51431000 | 0x7ffc51452000 |   rw- |     0x0 |     0 |     0 |     0 |                          [stack] |    Disabled
* | 1168 |  dnsmasq | 0x7ffc51592000 | 0x7ffc51596000 |   r-- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1168 |  dnsmasq | 0x7ffc51596000 | 0x7ffc51597000 |   r-x |     0x0 |     0 |     0 |     0 |                           [vdso] |    Disabled
* | 1174 |  dnsmasq | 0x558730c12000 | 0x558730c1a000 |   r-- |     0x0 |   254 |     0 |  1333 |                /usr/sbin/dnsmasq |    Disabled
* | 1174 |  dnsmasq | 0x558730c1a000 | 0x558730c43000 |   r-x |  0x8000 |   254 |     0 |  1333 |                /usr/sbin/dnsmasq |    Disabled
* | 1174 |  dnsmasq | 0x558730c43000 | 0x558730c4f000 |   r-- | 0x31000 |   254 |     0 |  1333 |                /usr/sbin/dnsmasq |    Disabled
* | 1174 |  dnsmasq | 0x558730c4f000 | 0x558730c52000 |   r-- | 0x3d000 |   254 |     0 |  1333 |                /usr/sbin/dnsmasq |    Disabled
* | 1174 |  dnsmasq | 0x558730c52000 | 0x558730c54000 |   rw- | 0x40000 |   254 |     0 |  1333 |                /usr/sbin/dnsmasq |    Disabled
* | 1174 |  dnsmasq | 0x55873264f000 | 0x558732650000 |   --- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1174 |  dnsmasq | 0x558732650000 | 0x558732651000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a00000 | 0x7f13d3a01000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a01000 | 0x7f13d3a02000 |   r-- |     0x0 |     0 |    20 |    36 |                          /etc/TZ |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a02000 | 0x7f13d3a33000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a33000 | 0x7f13d3a37000 |   r-- |     0x0 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a37000 | 0x7f13d3a46000 |   r-x |  0x4000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a46000 | 0x7f13d3a49000 |   r-- | 0x13000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a49000 | 0x7f13d3a4a000 |   r-- | 0x15000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a4a000 | 0x7f13d3a4b000 |   rw- | 0x16000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a4b000 | 0x7f13d3a4d000 |   r-- |     0x0 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a4d000 | 0x7f13d3a50000 |   r-x |  0x2000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a50000 | 0x7f13d3a52000 |   r-- |  0x5000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a52000 | 0x7f13d3a53000 |   r-- |  0x6000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a53000 | 0x7f13d3a54000 |   rw- |  0x7000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a54000 | 0x7f13d3a57000 |   r-- |     0x0 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a57000 | 0x7f13d3a5c000 |   r-x |  0x3000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a5c000 | 0x7f13d3a5f000 |   r-- |  0x8000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a5f000 | 0x7f13d3a60000 |   r-- |  0xa000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a60000 | 0x7f13d3a61000 |   rw- |  0xb000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a61000 | 0x7f13d3a75000 |   r-- |     0x0 |   254 |     0 |   361 |         /lib/ld-musl-x86_64.so.1 |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3a75000 | 0x7f13d3ac1000 |   r-x | 0x14000 |   254 |     0 |   361 |         /lib/ld-musl-x86_64.so.1 |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3ac1000 | 0x7f13d3ad6000 |   r-- | 0x60000 |   254 |     0 |   361 |         /lib/ld-musl-x86_64.so.1 |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3ad6000 | 0x7f13d3ad7000 |   r-- | 0x74000 |   254 |     0 |   361 |         /lib/ld-musl-x86_64.so.1 |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3ad7000 | 0x7f13d3ad8000 |   rw- | 0x75000 |   254 |     0 |   361 |         /lib/ld-musl-x86_64.so.1 |    Disabled
* | 1174 |  dnsmasq | 0x7f13d3ad8000 | 0x7f13d3adb000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1174 |  dnsmasq | 0x7ffea3a23000 | 0x7ffea3a44000 |   rw- |     0x0 |     0 |     0 |     0 |                          [stack] |    Disabled
* | 1174 |  dnsmasq | 0x7ffea3abe000 | 0x7ffea3ac2000 |   r-- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1174 |  dnsmasq | 0x7ffea3ac2000 | 0x7ffea3ac3000 |   r-x |     0x0 |     0 |     0 |     0 |                           [vdso] |    Disabled
* | 1244 | dropbear | 0x55c4d6771000 | 0x55c4d6775000 |   r-- |     0x0 |   254 |     0 |  1334 |               /usr/sbin/dropbear |    Disabled
* | 1244 | dropbear | 0x55c4d6775000 | 0x55c4d6795000 |   r-x |  0x4000 |   254 |     0 |  1334 |               /usr/sbin/dropbear |    Disabled
* | 1244 | dropbear | 0x55c4d6795000 | 0x55c4d67a1000 |   r-- | 0x24000 |   254 |     0 |  1334 |               /usr/sbin/dropbear |    Disabled
* | 1244 | dropbear | 0x55c4d67a1000 | 0x55c4d67a3000 |   r-- | 0x30000 |   254 |     0 |  1334 |               /usr/sbin/dropbear |    Disabled
* | 1244 | dropbear | 0x55c4d67a3000 | 0x55c4d67a4000 |   rw- | 0x32000 |   254 |     0 |  1334 |               /usr/sbin/dropbear |    Disabled
* | 1244 | dropbear | 0x55c4d67a4000 | 0x55c4d67a5000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1244 | dropbear | 0x55c4d7c29000 | 0x55c4d7c2a000 |   --- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1244 | dropbear | 0x55c4d7c2a000 | 0x55c4d7c2b000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1244 | dropbear | 0x7fe0e9f16000 | 0x7fe0e9f1a000 |   r-- |     0x0 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1244 | dropbear | 0x7fe0e9f1a000 | 0x7fe0e9f29000 |   r-x |  0x4000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1244 | dropbear | 0x7fe0e9f29000 | 0x7fe0e9f2c000 |   r-- | 0x13000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1244 | dropbear | 0x7fe0e9f2c000 | 0x7fe0e9f2d000 |   r-- | 0x15000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1244 | dropbear | 0x7fe0e9f2d000 | 0x7fe0e9f2e000 |   rw- | 0x16000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1244 | dropbear | 0x7fe0e9f2e000 | 0x7fe0e9f42000 |   r-- |     0x0 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1244 | dropbear | 0x7fe0e9f42000 | 0x7fe0e9f8e000 |   r-x | 0x14000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1244 | dropbear | 0x7fe0e9f8e000 | 0x7fe0e9fa3000 |   r-- | 0x60000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1244 | dropbear | 0x7fe0e9fa3000 | 0x7fe0e9fa4000 |   r-- | 0x74000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1244 | dropbear | 0x7fe0e9fa4000 | 0x7fe0e9fa5000 |   rw- | 0x75000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1244 | dropbear | 0x7fe0e9fa5000 | 0x7fe0e9fa8000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1244 | dropbear | 0x7ffc2da78000 | 0x7ffc2da99000 |   rw- |     0x0 |     0 |     0 |     0 |                          [stack] |    Disabled
* | 1244 | dropbear | 0x7ffc2db42000 | 0x7ffc2db46000 |   r-- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1244 | dropbear | 0x7ffc2db46000 | 0x7ffc2db47000 |   r-x |     0x0 |     0 |     0 |     0 |                           [vdso] |    Disabled
* | 1405 |   netifd |       0x400000 |       0x404000 |   r-- |     0x0 |   254 |     0 |   572 |                     /sbin/netifd |    Disabled
* | 1405 |   netifd |       0x404000 |       0x422000 |   r-x |  0x4000 |   254 |     0 |   572 |                     /sbin/netifd |    Disabled
* | 1405 |   netifd |       0x422000 |       0x430000 |   r-- | 0x22000 |   254 |     0 |   572 |                     /sbin/netifd |    Disabled
* | 1405 |   netifd |       0x430000 |       0x431000 |   r-- | 0x2f000 |   254 |     0 |   572 |                     /sbin/netifd |    Disabled
* | 1405 |   netifd |       0x431000 |       0x432000 |   rw- | 0x30000 |   254 |     0 |   572 |                     /sbin/netifd |    Disabled
* | 1405 |   netifd |       0x432000 |       0x433000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1405 |   netifd |      0x1ac7000 |      0x1ac8000 |   --- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1405 |   netifd |      0x1ac8000 |      0x1aca000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1405 |   netifd | 0x7f3d3b3be000 | 0x7f3d3b3c6000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1405 |   netifd | 0x7f3d3b3cb000 | 0x7f3d3b3cd000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1405 |   netifd | 0x7f3d3b3db000 | 0x7f3d3b3ee000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1405 |   netifd | 0x7f3d3b3ee000 | 0x7f3d3b3f2000 |   r-- |     0x0 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1405 |   netifd | 0x7f3d3b3f2000 | 0x7f3d3b401000 |   r-x |  0x4000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1405 |   netifd | 0x7f3d3b401000 | 0x7f3d3b404000 |   r-- | 0x13000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1405 |   netifd | 0x7f3d3b404000 | 0x7f3d3b405000 |   r-- | 0x15000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1405 |   netifd | 0x7f3d3b405000 | 0x7f3d3b406000 |   rw- | 0x16000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1405 |   netifd | 0x7f3d3b406000 | 0x7f3d3b409000 |   r-- |     0x0 |   254 |     0 |   753 |         /usr/lib/libnl-tiny.so.1 |    Disabled
* | 1405 |   netifd | 0x7f3d3b409000 | 0x7f3d3b40c000 |   r-x |  0x3000 |   254 |     0 |   753 |         /usr/lib/libnl-tiny.so.1 |    Disabled
* | 1405 |   netifd | 0x7f3d3b40c000 | 0x7f3d3b40e000 |   r-- |  0x6000 |   254 |     0 |   753 |         /usr/lib/libnl-tiny.so.1 |    Disabled
* | 1405 |   netifd | 0x7f3d3b40e000 | 0x7f3d3b40f000 |   r-- |  0x8000 |   254 |     0 |   753 |         /usr/lib/libnl-tiny.so.1 |    Disabled
* | 1405 |   netifd | 0x7f3d3b40f000 | 0x7f3d3b410000 |   rw- |  0x9000 |   254 |     0 |   753 |         /usr/lib/libnl-tiny.so.1 |    Disabled
* | 1405 |   netifd | 0x7f3d3b410000 | 0x7f3d3b411000 |   r-- |     0x0 |   254 |     0 |   360 | /lib/libblobmsg_json.so.20230523 |    Disabled
* | 1405 |   netifd | 0x7f3d3b411000 | 0x7f3d3b412000 |   r-x |  0x1000 |   254 |     0 |   360 | /lib/libblobmsg_json.so.20230523 |    Disabled
* | 1405 |   netifd | 0x7f3d3b412000 | 0x7f3d3b413000 |   r-- |  0x2000 |   254 |     0 |   360 | /lib/libblobmsg_json.so.20230523 |    Disabled
* | 1405 |   netifd | 0x7f3d3b413000 | 0x7f3d3b414000 |   r-- |  0x2000 |   254 |     0 |   360 | /lib/libblobmsg_json.so.20230523 |    Disabled
* | 1405 |   netifd | 0x7f3d3b414000 | 0x7f3d3b415000 |   rw- |  0x3000 |   254 |     0 |   360 | /lib/libblobmsg_json.so.20230523 |    Disabled
* | 1405 |   netifd | 0x7f3d3b415000 | 0x7f3d3b419000 |   r-- |     0x0 |   254 |     0 |   727 |      /usr/lib/libjson-c.so.5.2.0 |    Disabled
* | 1405 |   netifd | 0x7f3d3b419000 | 0x7f3d3b421000 |   r-x |  0x4000 |   254 |     0 |   727 |      /usr/lib/libjson-c.so.5.2.0 |    Disabled
* | 1405 |   netifd | 0x7f3d3b421000 | 0x7f3d3b424000 |   r-- |  0xc000 |   254 |     0 |   727 |      /usr/lib/libjson-c.so.5.2.0 |    Disabled
* | 1405 |   netifd | 0x7f3d3b424000 | 0x7f3d3b425000 |   r-- |  0xf000 |   254 |     0 |   727 |      /usr/lib/libjson-c.so.5.2.0 |    Disabled
* | 1405 |   netifd | 0x7f3d3b425000 | 0x7f3d3b426000 |   rw- | 0x10000 |   254 |     0 |   727 |      /usr/lib/libjson-c.so.5.2.0 |    Disabled
* | 1405 |   netifd | 0x7f3d3b426000 | 0x7f3d3b428000 |   r-- |     0x0 |   254 |     0 |   370 |                   /lib/libuci.so |    Disabled
* | 1405 |   netifd | 0x7f3d3b428000 | 0x7f3d3b42e000 |   r-x |  0x2000 |   254 |     0 |   370 |                   /lib/libuci.so |    Disabled
* | 1405 |   netifd | 0x7f3d3b42e000 | 0x7f3d3b430000 |   r-- |  0x8000 |   254 |     0 |   370 |                   /lib/libuci.so |    Disabled
* | 1405 |   netifd | 0x7f3d3b430000 | 0x7f3d3b431000 |   r-- |  0x9000 |   254 |     0 |   370 |                   /lib/libuci.so |    Disabled
* | 1405 |   netifd | 0x7f3d3b431000 | 0x7f3d3b432000 |   rw- |  0xa000 |   254 |     0 |   370 |                   /lib/libuci.so |    Disabled
* | 1405 |   netifd | 0x7f3d3b432000 | 0x7f3d3b434000 |   r-- |     0x0 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1405 |   netifd | 0x7f3d3b434000 | 0x7f3d3b437000 |   r-x |  0x2000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1405 |   netifd | 0x7f3d3b437000 | 0x7f3d3b439000 |   r-- |  0x5000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1405 |   netifd | 0x7f3d3b439000 | 0x7f3d3b43a000 |   r-- |  0x6000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1405 |   netifd | 0x7f3d3b43a000 | 0x7f3d3b43b000 |   rw- |  0x7000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1405 |   netifd | 0x7f3d3b43b000 | 0x7f3d3b43e000 |   r-- |     0x0 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1405 |   netifd | 0x7f3d3b43e000 | 0x7f3d3b443000 |   r-x |  0x3000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1405 |   netifd | 0x7f3d3b443000 | 0x7f3d3b446000 |   r-- |  0x8000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1405 |   netifd | 0x7f3d3b446000 | 0x7f3d3b447000 |   r-- |  0xa000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1405 |   netifd | 0x7f3d3b447000 | 0x7f3d3b448000 |   rw- |  0xb000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1405 |   netifd | 0x7f3d3b448000 | 0x7f3d3b45c000 |   r-- |     0x0 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1405 |   netifd | 0x7f3d3b45c000 | 0x7f3d3b4a8000 |   r-x | 0x14000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1405 |   netifd | 0x7f3d3b4a8000 | 0x7f3d3b4bd000 |   r-- | 0x60000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1405 |   netifd | 0x7f3d3b4bd000 | 0x7f3d3b4be000 |   r-- | 0x74000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1405 |   netifd | 0x7f3d3b4be000 | 0x7f3d3b4bf000 |   rw- | 0x75000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1405 |   netifd | 0x7f3d3b4bf000 | 0x7f3d3b4c2000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1405 |   netifd | 0x7ffddeca5000 | 0x7ffddecc6000 |   rw- |     0x0 |     0 |     0 |     0 |                          [stack] |    Disabled
* | 1405 |   netifd | 0x7ffdded41000 | 0x7ffdded45000 |   r-- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1405 |   netifd | 0x7ffdded45000 | 0x7ffdded46000 |   r-x |     0x0 |     0 |     0 |     0 |                           [vdso] |    Disabled
* | 1524 |   odhcpd | 0x558033ac3000 | 0x558033ac7000 |   r-- |     0x0 |   254 |     0 |  1341 |                 /usr/sbin/odhcpd |    Disabled
* | 1524 |   odhcpd | 0x558033ac7000 | 0x558033ad4000 |   r-x |  0x4000 |   254 |     0 |  1341 |                 /usr/sbin/odhcpd |    Disabled
* | 1524 |   odhcpd | 0x558033ad4000 | 0x558033ad7000 |   r-- | 0x11000 |   254 |     0 |  1341 |                 /usr/sbin/odhcpd |    Disabled
* | 1524 |   odhcpd | 0x558033ad7000 | 0x558033ad8000 |   r-- | 0x14000 |   254 |     0 |  1341 |                 /usr/sbin/odhcpd |    Disabled
* | 1524 |   odhcpd | 0x558033ad8000 | 0x558033ad9000 |   rw- | 0x15000 |   254 |     0 |  1341 |                 /usr/sbin/odhcpd |    Disabled
* | 1524 |   odhcpd | 0x5580348ee000 | 0x5580348ef000 |   --- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1524 |   odhcpd | 0x5580348ef000 | 0x5580348f0000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1524 |   odhcpd | 0x7fe9f6858000 | 0x7fe9f686a000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1524 |   odhcpd | 0x7fe9f686a000 | 0x7fe9f686e000 |   r-- |     0x0 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f686e000 | 0x7fe9f687d000 |   r-x |  0x4000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f687d000 | 0x7fe9f6880000 |   r-- | 0x13000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f6880000 | 0x7fe9f6881000 |   r-- | 0x15000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f6881000 | 0x7fe9f6882000 |   rw- | 0x16000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f6882000 | 0x7fe9f6884000 |   r-- |     0x0 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f6884000 | 0x7fe9f6887000 |   r-x |  0x2000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f6887000 | 0x7fe9f6889000 |   r-- |  0x5000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f6889000 | 0x7fe9f688a000 |   r-- |  0x6000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f688a000 | 0x7fe9f688b000 |   rw- |  0x7000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f688b000 | 0x7fe9f688e000 |   r-- |     0x0 |   254 |     0 |   753 |         /usr/lib/libnl-tiny.so.1 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f688e000 | 0x7fe9f6891000 |   r-x |  0x3000 |   254 |     0 |   753 |         /usr/lib/libnl-tiny.so.1 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f6891000 | 0x7fe9f6893000 |   r-- |  0x6000 |   254 |     0 |   753 |         /usr/lib/libnl-tiny.so.1 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f6893000 | 0x7fe9f6894000 |   r-- |  0x8000 |   254 |     0 |   753 |         /usr/lib/libnl-tiny.so.1 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f6894000 | 0x7fe9f6895000 |   rw- |  0x9000 |   254 |     0 |   753 |         /usr/lib/libnl-tiny.so.1 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f6895000 | 0x7fe9f6897000 |   r-- |     0x0 |   254 |     0 |   370 |                   /lib/libuci.so |    Disabled
* | 1524 |   odhcpd | 0x7fe9f6897000 | 0x7fe9f689d000 |   r-x |  0x2000 |   254 |     0 |   370 |                   /lib/libuci.so |    Disabled
* | 1524 |   odhcpd | 0x7fe9f689d000 | 0x7fe9f689f000 |   r-- |  0x8000 |   254 |     0 |   370 |                   /lib/libuci.so |    Disabled
* | 1524 |   odhcpd | 0x7fe9f689f000 | 0x7fe9f68a0000 |   r-- |  0x9000 |   254 |     0 |   370 |                   /lib/libuci.so |    Disabled
* | 1524 |   odhcpd | 0x7fe9f68a0000 | 0x7fe9f68a1000 |   rw- |  0xa000 |   254 |     0 |   370 |                   /lib/libuci.so |    Disabled
* | 1524 |   odhcpd | 0x7fe9f68a1000 | 0x7fe9f68a4000 |   r-- |     0x0 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f68a4000 | 0x7fe9f68a9000 |   r-x |  0x3000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f68a9000 | 0x7fe9f68ac000 |   r-- |  0x8000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f68ac000 | 0x7fe9f68ad000 |   r-- |  0xa000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f68ad000 | 0x7fe9f68ae000 |   rw- |  0xb000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1524 |   odhcpd | 0x7fe9f68ae000 | 0x7fe9f68c2000 |   r-- |     0x0 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1524 |   odhcpd | 0x7fe9f68c2000 | 0x7fe9f690e000 |   r-x | 0x14000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1524 |   odhcpd | 0x7fe9f690e000 | 0x7fe9f6923000 |   r-- | 0x60000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1524 |   odhcpd | 0x7fe9f6923000 | 0x7fe9f6924000 |   r-- | 0x74000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1524 |   odhcpd | 0x7fe9f6924000 | 0x7fe9f6925000 |   rw- | 0x75000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1524 |   odhcpd | 0x7fe9f6925000 | 0x7fe9f6928000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1524 |   odhcpd | 0x7fff193df000 | 0x7fff19400000 |   rw- |     0x0 |     0 |     0 |     0 |                          [stack] |    Disabled
* | 1524 |   odhcpd | 0x7fff19456000 | 0x7fff1945a000 |   r-- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1524 |   odhcpd | 0x7fff1945a000 | 0x7fff1945b000 |   r-x |     0x0 |     0 |     0 |     0 |                           [vdso] |    Disabled
* | 1552 |        4 | 0x564595660000 | 0x564595661000 |   r-- |     0x0 |     0 |     1 |     3 |               /memfd:x (deleted) |    Disabled
* | 1552 |        4 | 0x564595661000 | 0x564595662000 |   r-x |  0x1000 |     0 |     1 |     3 |               /memfd:x (deleted) |    Disabled
* | 1552 |        4 | 0x564595662000 | 0x564595663000 |   r-- |  0x2000 |     0 |     1 |     3 |               /memfd:x (deleted) |    Disabled
* | 1552 |        4 | 0x564595663000 | 0x564595664000 |   r-- |  0x2000 |     0 |     1 |     3 |               /memfd:x (deleted) |    Disabled
* | 1552 |        4 | 0x564595664000 | 0x564595665000 |   rw- |  0x3000 |     0 |     1 |     3 |               /memfd:x (deleted) |    Disabled
* | 1552 |        4 | 0x56459632f000 | 0x564596330000 |   --- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1552 |        4 | 0x564596330000 | 0x564596331000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1552 |        4 | 0x7f3b2d6ec000 | 0x7f3b2d6ed000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1552 |        4 | 0x7f3b2d6ed000 | 0x7f3b2d701000 |   r-- |     0x0 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1552 |        4 | 0x7f3b2d701000 | 0x7f3b2d74d000 |   r-x | 0x14000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1552 |        4 | 0x7f3b2d74d000 | 0x7f3b2d762000 |   r-- | 0x60000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1552 |        4 | 0x7f3b2d762000 | 0x7f3b2d763000 |   r-- | 0x74000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1552 |        4 | 0x7f3b2d763000 | 0x7f3b2d764000 |   rw- | 0x75000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1552 |        4 | 0x7f3b2d764000 | 0x7f3b2d767000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1552 |        4 | 0x7fffbde5b000 | 0x7fffbde7c000 |   rw- |     0x0 |     0 |     0 |     0 |                          [stack] |    Disabled
* | 1552 |        4 | 0x7fffbdf75000 | 0x7fffbdf79000 |   r-- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1552 |        4 | 0x7fffbdf79000 | 0x7fffbdf7a000 |   r-x |     0x0 |     0 |     0 |     0 |                           [vdso] |    Disabled
* | 1744 |     ntpd | 0x55f9df386000 | 0x55f9df38d000 |   r-- |     0x0 |   254 |     0 |   592 |                      /sbin/ujail |    Disabled
* | 1744 |     ntpd | 0x55f9df38d000 | 0x55f9df399000 |   r-x |  0x7000 |   254 |     0 |   592 |                      /sbin/ujail |    Disabled
* | 1744 |     ntpd | 0x55f9df399000 | 0x55f9df39e000 |   r-- | 0x13000 |   254 |     0 |   592 |                      /sbin/ujail |    Disabled
* | 1744 |     ntpd | 0x55f9df39e000 | 0x55f9df3a0000 |   r-- | 0x18000 |   254 |     0 |   592 |                      /sbin/ujail |    Disabled
* | 1744 |     ntpd | 0x55f9df3a0000 | 0x55f9df3a1000 |   rw- | 0x1a000 |   254 |     0 |   592 |                      /sbin/ujail |    Disabled
* | 1744 |     ntpd | 0x55f9df3a1000 | 0x55f9df4a3000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1744 |     ntpd | 0x55f9e0c1e000 | 0x55f9e0c1f000 |   --- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1744 |     ntpd | 0x55f9e0c1f000 | 0x55f9e0c20000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1744 |     ntpd | 0x7fa31d036000 | 0x7fa31d047000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1744 |     ntpd | 0x7fa31d047000 | 0x7fa31d04b000 |   r-- |     0x0 |   254 |     0 |   727 |      /usr/lib/libjson-c.so.5.2.0 |    Disabled
* | 1744 |     ntpd | 0x7fa31d04b000 | 0x7fa31d053000 |   r-x |  0x4000 |   254 |     0 |   727 |      /usr/lib/libjson-c.so.5.2.0 |    Disabled
* | 1744 |     ntpd | 0x7fa31d053000 | 0x7fa31d056000 |   r-- |  0xc000 |   254 |     0 |   727 |      /usr/lib/libjson-c.so.5.2.0 |    Disabled
* | 1744 |     ntpd | 0x7fa31d056000 | 0x7fa31d057000 |   r-- |  0xf000 |   254 |     0 |   727 |      /usr/lib/libjson-c.so.5.2.0 |    Disabled
* | 1744 |     ntpd | 0x7fa31d057000 | 0x7fa31d058000 |   rw- | 0x10000 |   254 |     0 |   727 |      /usr/lib/libjson-c.so.5.2.0 |    Disabled
* | 1744 |     ntpd | 0x7fa31d058000 | 0x7fa31d05c000 |   r-- |     0x0 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1744 |     ntpd | 0x7fa31d05c000 | 0x7fa31d06b000 |   r-x |  0x4000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1744 |     ntpd | 0x7fa31d06b000 | 0x7fa31d06e000 |   r-- | 0x13000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1744 |     ntpd | 0x7fa31d06e000 | 0x7fa31d06f000 |   r-- | 0x15000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1744 |     ntpd | 0x7fa31d06f000 | 0x7fa31d070000 |   rw- | 0x16000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1744 |     ntpd | 0x7fa31d070000 | 0x7fa31d071000 |   r-- |     0x0 |   254 |     0 |   360 | /lib/libblobmsg_json.so.20230523 |    Disabled
* | 1744 |     ntpd | 0x7fa31d071000 | 0x7fa31d072000 |   r-x |  0x1000 |   254 |     0 |   360 | /lib/libblobmsg_json.so.20230523 |    Disabled
* | 1744 |     ntpd | 0x7fa31d072000 | 0x7fa31d073000 |   r-- |  0x2000 |   254 |     0 |   360 | /lib/libblobmsg_json.so.20230523 |    Disabled
* | 1744 |     ntpd | 0x7fa31d073000 | 0x7fa31d074000 |   r-- |  0x2000 |   254 |     0 |   360 | /lib/libblobmsg_json.so.20230523 |    Disabled
* | 1744 |     ntpd | 0x7fa31d074000 | 0x7fa31d075000 |   rw- |  0x3000 |   254 |     0 |   360 | /lib/libblobmsg_json.so.20230523 |    Disabled
* | 1744 |     ntpd | 0x7fa31d075000 | 0x7fa31d077000 |   r-- |     0x0 |   254 |     0 |   370 |                   /lib/libuci.so |    Disabled
* | 1744 |     ntpd | 0x7fa31d077000 | 0x7fa31d07d000 |   r-x |  0x2000 |   254 |     0 |   370 |                   /lib/libuci.so |    Disabled
* | 1744 |     ntpd | 0x7fa31d07d000 | 0x7fa31d07f000 |   r-- |  0x8000 |   254 |     0 |   370 |                   /lib/libuci.so |    Disabled
* | 1744 |     ntpd | 0x7fa31d07f000 | 0x7fa31d080000 |   r-- |  0x9000 |   254 |     0 |   370 |                   /lib/libuci.so |    Disabled
* | 1744 |     ntpd | 0x7fa31d080000 | 0x7fa31d081000 |   rw- |  0xa000 |   254 |     0 |   370 |                   /lib/libuci.so |    Disabled
* | 1744 |     ntpd | 0x7fa31d081000 | 0x7fa31d083000 |   r-- |     0x0 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1744 |     ntpd | 0x7fa31d083000 | 0x7fa31d086000 |   r-x |  0x2000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1744 |     ntpd | 0x7fa31d086000 | 0x7fa31d088000 |   r-- |  0x5000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1744 |     ntpd | 0x7fa31d088000 | 0x7fa31d089000 |   r-- |  0x6000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1744 |     ntpd | 0x7fa31d089000 | 0x7fa31d08a000 |   rw- |  0x7000 |   254 |     0 |   369 |         /lib/libubus.so.20230605 |    Disabled
* | 1744 |     ntpd | 0x7fa31d08a000 | 0x7fa31d08d000 |   r-- |     0x0 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1744 |     ntpd | 0x7fa31d08d000 | 0x7fa31d092000 |   r-x |  0x3000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1744 |     ntpd | 0x7fa31d092000 | 0x7fa31d095000 |   r-- |  0x8000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1744 |     ntpd | 0x7fa31d095000 | 0x7fa31d096000 |   r-- |  0xa000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1744 |     ntpd | 0x7fa31d096000 | 0x7fa31d097000 |   rw- |  0xb000 |   254 |     0 |   368 |         /lib/libubox.so.20230523 |    Disabled
* | 1744 |     ntpd | 0x7fa31d097000 | 0x7fa31d0ab000 |   r-- |     0x0 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1744 |     ntpd | 0x7fa31d0ab000 | 0x7fa31d0f7000 |   r-x | 0x14000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1744 |     ntpd | 0x7fa31d0f7000 | 0x7fa31d10c000 |   r-- | 0x60000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1744 |     ntpd | 0x7fa31d10c000 | 0x7fa31d10d000 |   r-- | 0x74000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1744 |     ntpd | 0x7fa31d10d000 | 0x7fa31d10e000 |   rw- | 0x75000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1744 |     ntpd | 0x7fa31d10e000 | 0x7fa31d111000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1744 |     ntpd | 0x7ffebeb09000 | 0x7ffebeb2a000 |   rw- |     0x0 |     0 |     0 |     0 |                          [stack] |    Disabled
* | 1744 |     ntpd | 0x7ffebebaa000 | 0x7ffebebae000 |   r-- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1744 |     ntpd | 0x7ffebebae000 | 0x7ffebebaf000 |   r-x |     0x0 |     0 |     0 |     0 |                           [vdso] |    Disabled
* | 1749 |     ntpd |       0x400000 |       0x406000 |   r-- |     0x0 |   254 |     0 |    15 |                   /usr/sbin/ntpd |    Disabled
* | 1749 |     ntpd |       0x406000 |       0x44e000 |   r-x |  0x6000 |   254 |     0 |    15 |                   /usr/sbin/ntpd |    Disabled
* | 1749 |     ntpd |       0x44e000 |       0x462000 |   r-- | 0x4e000 |   254 |     0 |    15 |                   /usr/sbin/ntpd |    Disabled
* | 1749 |     ntpd |       0x462000 |       0x463000 |   r-- | 0x62000 |   254 |     0 |    15 |                   /usr/sbin/ntpd |    Disabled
* | 1749 |     ntpd |       0x463000 |       0x464000 |   rw- | 0x63000 |   254 |     0 |    15 |                   /usr/sbin/ntpd |    Disabled
* | 1749 |     ntpd |      0x1355000 |      0x1356000 |   --- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1749 |     ntpd |      0x1356000 |      0x1357000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1749 |     ntpd | 0x7fceb6ef0000 | 0x7fceb6ef4000 |   r-- |     0x0 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1749 |     ntpd | 0x7fceb6ef4000 | 0x7fceb6f03000 |   r-x |  0x4000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1749 |     ntpd | 0x7fceb6f03000 | 0x7fceb6f06000 |   r-- | 0x13000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1749 |     ntpd | 0x7fceb6f06000 | 0x7fceb6f07000 |   r-- | 0x15000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1749 |     ntpd | 0x7fceb6f07000 | 0x7fceb6f08000 |   rw- | 0x16000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1749 |     ntpd | 0x7fceb6f08000 | 0x7fceb6f1c000 |   r-- |     0x0 |   254 |     0 |   361 |         /lib/ld-musl-x86_64.so.1 |    Disabled
* | 1749 |     ntpd | 0x7fceb6f1c000 | 0x7fceb6f68000 |   r-x | 0x14000 |   254 |     0 |   361 |         /lib/ld-musl-x86_64.so.1 |    Disabled
* | 1749 |     ntpd | 0x7fceb6f68000 | 0x7fceb6f7d000 |   r-- | 0x60000 |   254 |     0 |   361 |         /lib/ld-musl-x86_64.so.1 |    Disabled
* | 1749 |     ntpd | 0x7fceb6f7d000 | 0x7fceb6f7e000 |   r-- | 0x74000 |   254 |     0 |   361 |         /lib/ld-musl-x86_64.so.1 |    Disabled
* | 1749 |     ntpd | 0x7fceb6f7e000 | 0x7fceb6f7f000 |   rw- | 0x75000 |   254 |     0 |   361 |         /lib/ld-musl-x86_64.so.1 |    Disabled
* | 1749 |     ntpd | 0x7fceb6f7f000 | 0x7fceb6f82000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1749 |     ntpd | 0x7ffca2b73000 | 0x7ffca2b94000 |   rw- |     0x0 |     0 |     0 |     0 |                          [stack] |    Disabled
* | 1749 |     ntpd | 0x7ffca2bdb000 | 0x7ffca2bdf000 |   r-- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1749 |     ntpd | 0x7ffca2bdf000 | 0x7ffca2be0000 |   r-x |     0x0 |     0 |     0 |     0 |                           [vdso] |    Disabled
* | 1854 |  service |       0x400000 |       0x406000 |   r-- |     0x0 |   254 |     0 |    15 |                     /bin/busybox |    Disabled
* | 1854 |  service |       0x406000 |       0x44e000 |   r-x |  0x6000 |   254 |     0 |    15 |                     /bin/busybox |    Disabled
* | 1854 |  service |       0x44e000 |       0x462000 |   r-- | 0x4e000 |   254 |     0 |    15 |                     /bin/busybox |    Disabled
* | 1854 |  service |       0x462000 |       0x463000 |   r-- | 0x62000 |   254 |     0 |    15 |                     /bin/busybox |    Disabled
* | 1854 |  service |       0x463000 |       0x464000 |   rw- | 0x63000 |   254 |     0 |    15 |                     /bin/busybox |    Disabled
* | 1854 |  service |       0xd9a000 |       0xd9b000 |   --- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1854 |  service |       0xd9b000 |       0xd9c000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1854 |  service | 0x7fec3225a000 | 0x7fec3225e000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1854 |  service | 0x7fec32260000 | 0x7fec32264000 |   r-- |     0x0 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1854 |  service | 0x7fec32264000 | 0x7fec32273000 |   r-x |  0x4000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1854 |  service | 0x7fec32273000 | 0x7fec32276000 |   r-- | 0x13000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1854 |  service | 0x7fec32276000 | 0x7fec32277000 |   r-- | 0x15000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1854 |  service | 0x7fec32277000 | 0x7fec32278000 |   rw- | 0x16000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1854 |  service | 0x7fec32278000 | 0x7fec3228c000 |   r-- |     0x0 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1854 |  service | 0x7fec3228c000 | 0x7fec322d8000 |   r-x | 0x14000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1854 |  service | 0x7fec322d8000 | 0x7fec322ed000 |   r-- | 0x60000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1854 |  service | 0x7fec322ed000 | 0x7fec322ee000 |   r-- | 0x74000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1854 |  service | 0x7fec322ee000 | 0x7fec322ef000 |   rw- | 0x75000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1854 |  service | 0x7fec322ef000 | 0x7fec322f2000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1854 |  service | 0x7ffc2bf3d000 | 0x7ffc2bf5e000 |   rw- |     0x0 |     0 |     0 |     0 |                          [stack] |    Disabled
* | 1854 |  service | 0x7ffc2bfaf000 | 0x7ffc2bfb3000 |   r-- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1854 |  service | 0x7ffc2bfb3000 | 0x7ffc2bfb4000 |   r-x |     0x0 |     0 |     0 |     0 |                           [vdso] |    Disabled
* | 1855 |  dnsmasq |       0x400000 |       0x406000 |   r-- |     0x0 |   254 |     0 |    15 |                     /bin/busybox |    Disabled
* | 1855 |  dnsmasq |       0x406000 |       0x44e000 |   r-x |  0x6000 |   254 |     0 |    15 |                     /bin/busybox |    Disabled
* | 1855 |  dnsmasq |       0x44e000 |       0x462000 |   r-- | 0x4e000 |   254 |     0 |    15 |                     /bin/busybox |    Disabled
* | 1855 |  dnsmasq |       0x462000 |       0x464000 |   rw- | 0x62000 |   254 |     0 |    15 |                     /bin/busybox |    Disabled
* | 1855 |  dnsmasq |      0x1f37000 |      0x1f38000 |   --- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1855 |  dnsmasq |      0x1f38000 |      0x1f39000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1855 |  dnsmasq | 0x7f275f5b4000 | 0x7f275f5b8000 |   r-- |     0x0 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1855 |  dnsmasq | 0x7f275f5b8000 | 0x7f275f5c7000 |   r-x |  0x4000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1855 |  dnsmasq | 0x7f275f5c7000 | 0x7f275f5ca000 |   r-- | 0x13000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1855 |  dnsmasq | 0x7f275f5ca000 | 0x7f275f5cc000 |   rw- | 0x15000 |   254 |     0 |   363 |               /lib/libgcc_s.so.1 |    Disabled
* | 1855 |  dnsmasq | 0x7f275f5cc000 | 0x7f275f5e0000 |   r-- |     0x0 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1855 |  dnsmasq | 0x7f275f5e0000 | 0x7f275f62c000 |   r-x | 0x14000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1855 |  dnsmasq | 0x7f275f62c000 | 0x7f275f641000 |   r-- | 0x60000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1855 |  dnsmasq | 0x7f275f641000 | 0x7f275f643000 |   rw- | 0x74000 |   254 |     0 |   361 |                     /lib/libc.so |    Disabled
* | 1855 |  dnsmasq | 0x7f275f643000 | 0x7f275f646000 |   rw- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1855 |  dnsmasq | 0x7ffcfda1a000 | 0x7ffcfda3b000 |   rw- |     0x0 |     0 |     0 |     0 |                          [stack] |    Disabled
* | 1855 |  dnsmasq | 0x7ffcfdaf1000 | 0x7ffcfdaf5000 |   r-- |     0x0 |     0 |     0 |     0 |                Anonymous Mapping |    Disabled
* | 1855 |  dnsmasq | 0x7ffcfdaf5000 | 0x7ffcfdaf6000 |   r-x |     0x0 |     0 |     0 |     0 |                           [vdso] |    Disabled
```

`vol -f .\memory.dump --symbol-dirs=./symbols linux.psaux.PsAux`
```
1018    1       logd    /sbin/logd -S 64
1168    1       dnsmasq /sbin/ujail -t 5 -n dnsmasq -u -l -r /bin/ubus -r /etc/TZ -r /etc/dnsmasq.conf -r /etc/ethers -r /etc/group -r /etc/hosts -r /etc/passwd -w /tmp/dhcp.leases -r /tmp/dnsmasq.d -r /tmp/hosts -r /tmp/resolv.conf.d -r /usr/bin/jshn -r /usr/lib/dnsmasq/dhcp-script.sh -r /usr/share/dnsmasq/dhcpbogushostname.conf -r /usr/share/dnsmasq/rfc6761.conf -r /usr/share/dnsmasq/trust-anchors.conf -r /usr/share/libubox/jshn.sh -r /var/etc/dnsmasq.conf.cfg01411c -w /var/run/dnsmasq/ -- /usr/sbin/dnsmasq -C /var/etc/dnsmasq.conf.cfg01411c -k -x /var/run/dnsmasq/dnsmasq.cfg01411c.pid
1174    1168    dnsmasq /usr/sbin/dnsmasq -C /var/etc/dnsmasq.conf.cfg01411c -k -x /var/run/dnsmasq/dnsmasq.cfg01411c.pid
1244    1       dropbear        /usr/sbin/dropbear -F -P /var/run/dropbear.1.pid -p 22 -K 300 -T 3
1405    1       netifd  /sbin/netifd
1524    1       odhcpd  /usr/sbin/odhcpd
1552    515     4       /bin/libnss-update /proc/self/fd/5
1744    1       ntpd    /sbin/ujail -t 5 -n ntpd -U ntp -G ntp -C /etc/capabilities/ntpd.json -c -u -r /bin/ubus -r /usr/bin/env -r /usr/bin/jshn -r /usr/sbin/ntpd-hotplug -r /usr/share/libubox/jshn.sh -- /usr/sbin/ntpd -n -N -S /usr/sbin/ntpd-hotplug -p 0.openwrt.pool.ntp.org -p 1.openwrt.pool.ntp.org -p 2.openwrt.pool.ntp.org -p 3.openwrt.pool.ntp.org
1749    1744    ntpd    /usr/sbin/ntpd -n -N -S /usr/sbin/ntpd-hotplug -p 0.openwrt.pool.ntp.org -p 1.openwrt.pool.ntp.org -p 2.openwrt.pool.ntp.org -p 3.openwrt.pool.ntp.org
1854    1552    service /bin/sh /sbin/service dnsmasq restart
1855    1854    dnsmasq /bin/sh /etc/rc.common /etc/init.d/dnsmasq restart
```

`vol -f .\memory.dump --symbol-dirs=./symbols linux.pslist`
```
* | 0x8880067fcb40 |  737 |  737 |    2 |        cfg80211 |   0 |   0 |    0 |    0 |             - |    Disabled
* | 0x88800631da40 | 1018 | 1018 |    1 |            logd | 514 | 514 |  514 |  514 |             - |    Disabled
* | 0x8880067f9e40 | 1168 | 1168 |    1 |         dnsmasq |   0 |   0 |    0 |    0 |             - |    Disabled
* | 0x8880067f8040 | 1174 | 1174 | 1168 |         dnsmasq | 453 | 453 |  453 |  453 |             - |    Disabled
* | 0x8880063c1e40 | 1244 | 1244 |    1 |        dropbear |   0 |   0 |    0 |    0 |             - |    Disabled
* | 0x888003f20040 | 1405 | 1405 |    1 |          netifd |   0 |   0 |    0 |    0 |             - |    Disabled
* | 0x88800631ad40 | 1524 | 1524 |    1 |          odhcpd |   0 |   0 |    0 |    0 |             - |    Disabled
* | 0x888003edad40 | 1552 | 1552 |  515 |               4 |   0 |   0 |    0 |    0 |             - |    Disabled
* | 0x8880067f8f40 | 1744 | 1744 |    1 |            ntpd |   0 |   0 |    0 |    0 |             - |    Disabled
* | 0x8880057acb40 | 1749 | 1749 | 1744 |            ntpd | 123 | 123 |  123 |  123 |             - |    Disabled
* | 0x8880063c0040 | 1854 | 1854 | 1552 |         service |   0 |   0 |    0 |    0 |             - |    Disabled
* | 0x8880063c2d40 | 1855 | 1855 | 1854 |         dnsmasq |   0 |   0 |    0 |    0 |             - |    Disabled
```

`vol -f .\memory.dump --symbol-dirs=./symbols -r pretty linux.pstree`
```
      |     OFFSET (V) |  PID |  TID | PPID |            COMM
*     | 0x88800329cb40 |    1 |    1 |    0 |           procd
**    | 0x88800534da40 |  514 |  514 |    1 |           ubusd
**    | 0x88800534bc40 |  515 |  515 |    1 |             ash
***   | 0x888003edad40 | 1552 | 1552 |  515 |               4
****  | 0x8880063c0040 | 1854 | 1854 | 1552 |         service
***** | 0x8880063c2d40 | 1855 | 1855 | 1854 |         dnsmasq
**    | 0x888005349e40 |  516 |  516 |    1 |        askfirst
**    | 0x888003edbc40 |  551 |  551 |    1 |           urngd
**    | 0x88800631da40 | 1018 | 1018 |    1 |            logd
**    | 0x8880067f9e40 | 1168 | 1168 |    1 |         dnsmasq
***   | 0x8880067f8040 | 1174 | 1174 | 1168 |         dnsmasq
**    | 0x8880063c1e40 | 1244 | 1244 |    1 |        dropbear
**    | 0x888003f20040 | 1405 | 1405 |    1 |          netifd
**    | 0x88800631ad40 | 1524 | 1524 |    1 |          odhcpd
**    | 0x8880067f8f40 | 1744 | 1744 |    1 |            ntpd
***   | 0x8880057acb40 | 1749 | 1749 | 1744 |            ntpd
```

`vol -f .\memory.dump --symbol-dirs=./symbols -r pretty linux.pagecache.Files --find /etc/hosts`
```
  | SuperblockAddr | MountPoint | Device | InodeNum |      InodeAddr | FileType | InodePages | CachedPages |   FileMode |                     AccessTime |               ModificationTime |                     ChangeTime |   FilePath | InodeSize
* | 0x88800570d000 |          / |  254:0 |       98 | 0x888005c011e8 |      REG |          1 |           1 | -rw-rw-r-- | 2023-10-09 21:45:35.000000 UTC | 2025-09-06 04:54:16.520000 UTC | 2025-09-06 04:54:16.520000 UTC | /etc/hosts |      1330
```

`vol -f .\memory.dump --symbol-dirs=./symbols linux.pagecache.InodePages --find /etc/hosts`
```
PageVAddr       PagePAddr       MappingAddr     Index   DumpSafe        Flags   Output File
ERROR    volatility3.framework.symbols.linux: Invalid cached page at 0x888007c14a40, aborting
WARNING  volatility3.plugins.linux.pagecache: Page cache for inode at 0x888005c011e8 is corrupt
```
`vol -f .\memory.dump --symbol-dirs=./symbols linux.elfs --dump`
`vol -f .\memory.dump --symbol-dirs=./symbols linux.proc.Maps --dump`

```
BusyBox v1.36.1 (2023-10-09 21:45:35 UTC) built-in shell (ash)

  _______                     ________        __
 |       |.-----.-----.-----.|  |  |  |.----.|  |_
 |   -   ||  _  |  -__|     ||  |  |  ||   _||   _|
 |_______||   __|_____|__|__||________||__|  |____|
          |__| W I R E L E S S   F R E E D O M
 -----------------------------------------------------
 OpenWrt 23.05.0, r23497-6637af95aa
 -----------------------------------------------------
=== WARNING! =====================================
There is no root password defined on this device!
Use the "passwd" command to set up a new password
in order to prevent unauthorized SSH logins.
--------------------------------------------------
root@OpenWrt:/# unset HISTFILE
root@OpenWrt:/# /bin/sh


BusyBox v1.36.1 (2023-10-09 21:45:35 UTC) built-in shell (ash)

root@OpenWrt:/# unset HISTFILE
root@OpenWrt:/# mkdir /tmp/run/upt && mount -t 9p -o trans=virtio,version=9p2000.L,cache=none KNL /tmp/run/upt && cp /tmp/run/upt/arm /bin/ && umount /tmp/run/upt && exit
root@OpenWrt:/# /bin/arm 2>&1 /dev/null
cfg file: /proc/self/fd/5
opening /proc/self/fd/5
opened /proc/self/fd/5
opening /etc/hosts
```


```
1bZl0Tq1mMvoclrs2X1DCwfYWsqVs+3PlCOPIuuVi79wtWBExuNZecf+QVz8ouWkEMFzKRl2S586pBzc09aQSjyY/A5t2t1/twQUZi5NTLtJvtvg67Zwsjt/9bEWHbeENziW2G5/pmDDgfvS7UHnQwY3cWMnyF258EFfsuRRkzctYTO0qWiWcwR5HlnsdNuXYW2IlWQH4o5nBbr7Z+FtdzJWzjvWOzJeDmFiojXHkXYP659qTYr65uw4aL0M3uywwskg+B8YTR+BgVtkzKVNOf2DAmn6ysT8IYYLv5z43P+0e6Q2LnVVz+dUZfLYkK1352Eu89X7nySJNZewsPg8duPfXHI/EKOVUXfyue/7c/1B6Mvj0QP4a8IcVEQ06I8OJ8i/U2H+If7way9ITqROuDdJW2+lM73pLBMSdZv/CGmTiZTLQ9Z/KVUYdYRxtErPl8bKVos7W7nJPVWzbYXLJz0FVKk/nLSFop0Cgx9Z2oAlIZlT/vNaFqapCssLU3FtS+lI4Ac6ODR9rj7WgTEhz6gT2315Pmrn+yT5GmcbeljreIXZ4fwLUK13gPUUPoeGWZgFCVI2tU+Dc5GwopvUffAkLc/QMly+2D9GTXa/62mRH34zQ7JflnJ2DlHAzEnPM0uv3CsSjPszQEV14l7eYAd1AHhkunvm96/oa0Sd/RF7axnLsjIiq4+OsB6mGr2Yhf84bevRWHk2B4qmbUnK8Ky3NawicVd9WHvPFal7TEcg9IEcfdWwWj+TsG9y/a7o7ArPO82p8c0dpDdz+YCc9hNtw6BbT/3mcaJpYh5RPzDeE/1rTFwIwgGA3DYeqJkt9VRJ4KzA0D/+Cl9xQnrefeLkLygmfJ4L4pN+bZfELPk0YGA0Vq1Xt0gvUjM1vW6zq1ZVqf8XYp+FZ3Os4XnkZVtjTy7YEPbqgNOCjyX4X175imsD5Hi+5v+6ZtJQ51diMQBM9i64qf2lBBmgnSEBvp8LRMZI3Ory3BakFOClno1GEJse1esEYI+pHDi7jsf3eZFeoCBeOA2qFJFNTVlYhf98H4vn6JcIK+HJRhJUMLNKqVMnTm+44WmkZBoOcbvKPgvEvaPuJq8sd6HC5tB2kXX0lMKuPxDb+2BN8tM9X92FS09BDqhxwp6zhbNjnQ6nYiRxVNfyS2vV7VJM7z74u4mZreERoBrW6vLKCIQaRoyZPVmqyXF21J0uIdMb+fiP/YVhzEoUlY2em1bFMGCF61gJ5X/E0oPXr65TqlcrSzczxl7AkWI215J+6wZS6fEXWZpK1MiW6o98i39kAUI7YZNEqvUDbpH4Gnicy4uGVxjMKa/Gq8bQPv4XA1cLg8QzSavXdRPQpz+rfik3S5o3rU1ELWgQCcMSjpPT61h8leYkRhtotQaRZbmegeYV7xbp9bPvfGW+nBojzaZqB5j2PnJmMelf4Vt8XXoYpyChJzB7VMvkNAe1nsTma6EweKCg3/RS/luPs66BRLUmTZmr79hrQfrZRhhGSNYN+6CQppRG6zuUTklDF9GiMl/9kXMUp2C4rCNpHR3wO8i+3Im6YqUgZ62tTyLZrkcq2skmMcBM8u6Myb1VoEW4OGQkM6Jqk80qIs6BartLHff/NXjBW//H8JK0FYA=
```

```
docker run -it alpine:latest /bin/sh
docker cp .\libnss-update.elf affectionate_ramanujan:/
docker cp .\base64-encoded+encrypted-data.txt affectionate_ramanujan:/
```

```
cat /etc/hosts
./libnss-update.elf base64-encoded+encrypted-data.txt
cat /etc/hosts
```

```
203.0.113.58 ports.ubuntu.com
203.0.113.58 dl-cdn.alpinelinux.org
203.0.113.67 pypi.io
203.0.113.58 us.archive.ubuntu.com
203.0.113.58 security.debian.org
203.0.113.58 security.ubuntu.com
203.0.113.52 mirrors.opensuse.org
203.0.113.58 archive.ubuntu.com
203.0.113.58 archive.archlinux.org
203.0.113.52 mirrors.rockylinux.org
203.0.113.52 mirror.stream.centos.org
203.0.113.58 download.opensuse.org
203.0.113.58 deb.debian.org
203.0.113.52 xmirror.voidlinux.org
203.0.113.52 mirrors.kernel.org
203.0.113.58 download1.rpmfusion.org
203.0.113.58 packages.linuxmint.com
203.0.113.58 cache.nixos.org
203.0.113.67 pypi.org
203.0.113.52 mirrors.fedoraproject.org
203.0.113.58 archive.ubuntu.org
203.0.113.58 security.ubuntu.org
203.0.113.52 geo.mirror.pkgbuild.com
203.0.113.58 ports.ubuntu.org
203.0.113.58 repo-default.voidlinux.org
203.0.113.58 distfiles.gentoo.org
203.0.113.67 files.pythonhosted.org
203.0.113.58 ftp.us.debian.org
203.0.113.67 pypi.python.org
203.0.113.58 dl.rockylinux.org
203.0.113.58 repos.opensuse.org
203.0.113.58 http.kali.org
203.0.113.52 mirrors.rpmfusion.org
203.0.113.58 repo.almalinux.org
203.0.113.52 mirror.rackspace.com
203.0.113.58 dl.fedoraproject.org
203.0.113.52 mirrors.alpinelinux.org
```

### Notes

Task 3 was the most time consuming of the challenge for me. 


## Result


<div align="center" 
     style="background-color: #dff0d8;
            border-color: #d6e9c6;
            color: #3c763d;
            padding: 15px;
            border-radius: 4px;
            font-family: Roboto, Helvetica, Arial, sans-serif;
            font-size: 14px;
            line-height: 1.42857143;">
Task Completed at Mon, 15 Dec 2025 02:38:41 GMT: 

---

Good work! Let's head back to NSA headquarters to continue with this analysis.

</div>

---

<div align="center">

![badge3.png](badge3.png)

</div>