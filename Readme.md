
# XDP-fastDNSC 
# XDP-FastDNSCaching Service.


A program that cached A/AAAA records and processes them ultra fast using XDP/eBPF offloading xdp program on NIC.

## Use cases
 
 Cache DNS queries that are most used for faster performance.

 Or integrate whatever you want! Endless possibilities!


## Features

 A/AAAA Records support
 DNSSEC support
 Upstream DNS support for caching records.
 Failover DNS Upstream support (Using multiple DNS Servers)
 Metrics Monitoring
 Round Robin support
 Advanced Caching and serving using XDP/eBPF



## Installation and Running

Install the dependencies

```bash
sudo apt install -y clang llvm libbpf-dev linux-tools-common linux-tools-$(uname -r) iproute2 libdns-dev
```

### Compile
```bash
clang -O2 -Wall -target bpf -I/usr/include/$(uname -m)-linux-gnu -c xdp-dns.c -o xdp-dns.o
gcc -Wall dns_loader.c -o dns_loader -lbpf -lldns -lpthread

```

#### Running

```bash
./xdp-loader eth0
```


