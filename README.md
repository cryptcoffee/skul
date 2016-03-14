      ██████  ██ ▄█▀ █    ██  ██▓    
    ▒██    ▒  ██▄█▒  ██  ▓██▒▓██▒    
    ░ ▓██▄   ▓███▄░ ▓██  ▒██░▒██░    
      ▒   ██▒▓██ █▄ ▓▓█  ░██░▒██░    
    ▒██████▒▒▒██▒ █▄▒▒█████▓ ░██████▒
    ▒ ▒▓▒ ▒ ░▒ ▒▒ ▓▒░▒▓▒ ▒ ▒ ░ ▒░▓  ░
    ░ ░▒  ░ ░░ ░▒ ▒░░░▒░ ░ ░ ░ ░ ▒  ░
    ░  ░  ░  ░ ░░ ░  ░░░ ░ ░   ░ ░   
          ░  ░  ░      ░         ░  ░
          
## Introduction
Skul is a tool for benchmarking LUKS encrypted partitions.

## Features
Most relevant features included in this release:

* Fast PBKDF2 implementation: we make use of [fastpbkdf2](https://github.com/ctz/fastpbkdf2), the most powerfull CPU-based implementation of PBKDF2. 
* Multi-thread support
* Fast master-key check: enables to speed-up the attack up to 20%
* Configurable incremental bruteforce attack mode
* Password-list attack mode

## Prerequisites
In order to run Skul is necessary to install OpenSSL library.

## Build Skul
```bash
$ ./configure 
$ make skul 
```

## Usage
To test Skul we provide some header of cryptsetup's encrypted disks:
```bash
$ ./skul disks/test_disk_py 
```
To test your own disk you need to dump the LUKS header of the partition:
```bash
$ dd if=/dev/sdX of=./my_dump bs=1024 count=3072
```
Then you can run:
```bash
$ ./skul ./my_dump
```

You can configure Skul thruogh its configuration file `conf/skul.cfg`

##Future improvings
We are working on:

* GPU-based implementation
* Password masking techniques to reduce the set of passwords in bruteforce mode
