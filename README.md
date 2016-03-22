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
Skul is a PoC to bruteforce the Cryptsetup implementation of Linux Unified Key Setup (LUKS).

Read about it [here](http://crypt.coffee/research/luks.html).

## Features
Most relevant features included in this release:

* Fast PBKDF2 implementation: we make use of [fastpbkdf2](https://github.com/ctz/fastpbkdf2), the most powerfull CPU-based implementation of PBKDF2. 
* Multi-thread support
* Fast master key check: enables the speed-up of the attack up to 20%
* Configurable incremental bruteforce attack mode
* Password-list attack mode

## Prerequisites
To run Skul the OpenSSL library is required.

## Build Skul

```bash
$ ./configure 
$ make skul 
```


## Usage
To test Skul we provide an example header of cryptsetup's encrypted disks:

```bash
$ ./skul disks/test_disk_py 
```
To test your own disk you need to dump the LUKS header of the partition:

```
# dd if=/dev/sdX of=./my_dump bs=1024 count=3072
```
Then you can run:

```bash
$ ./skul ./my_dump
```

You can configure Skul thruogh its configuration file `conf/skul.cfg`
