# SNT - Simple Network Tool
[![Actions Build Status](https://github.com/voldien/snt/workflows/snt/badge.svg?branch=master)](https://github.com/voldien/snt/actions)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![GitHub release](https://img.shields.io/github/release/voldien/snt.svg)](https://github.com/voldien/snt/releases)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/voldien/snt.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/voldien/snt/context:cpp)

*snt* - simple-network-tool is a network tool for performing network performance tests. The program supports multiple benchmark modes for testing various aspect of the network. The benchmark can use compression and encryption optionally in order to check how encryption and compression will change the network performance.

The *snt* program uses the server/client connection model. Where the server and client is executed on the same executable binary.

*Benchmark modes*

* Performance - Send as much data as possible by specified payload size.
* Integrity - Sends a number sequence or time stamp to compare the arrival in order to check if they arrived in a consecutive order or not.
* File-Transfer - Send a file, used for repeatable benchmark testing when using encryption and compression.

# Motivation

This project was created for educational purposes. It was created in order learn about creating a secure connection with asymmetric and symmetric ciphers.

## Installation

The program is installed with the following commands.
```
mkdir build
cd build
cmake ..
make
```
## Wireshark
The wireshark dissector for decoding snt packets with the wireshark program can be installed with the following command:
```
make install_wireshark
```
This will install a lua script in the $(USER)/.wireshark directory.

## Service
The service script can be installed to run the snt program as a deamon service. This can be done with the following command:
```bash
make insall_service 
```
```bash
make install_systemd_service
```
The service can be started as followed:
```bash
service sntd start
```

## Certificates
The snt program support loading certificate and PEM files at startup. The snt default settings is to load a certifcate and a PEM file from the filesystem.
The following command will generate the certificate, private key and diffie hellman parameter. This may take a long time because diffie hellman is set to 2048 bit. This can overriden by appending the argument DHPARAM=1024, this would change the diffie hellman from its default 2048 bit to 1024 bit.
```bash
make cert
make install_cert
```

## Examples

This section cover some examples of how to use the *snt* program. See *snt*(1) for what command line options are available for usage.

## Client
Running in client mode requires at least the *-h* option with the hostname or IP address argument of the server that it shall connect to. The *snt* program is by default set to run as a client.
```
snt -h localhost --secure --compression -b performance --verbose
```
Using the file benchmark mode.
```
snt -h localhost --secure --compression -b file --file='valid path' --verbose
```
Specifying a compression algorithm. Valid options are: lz4, gzip, and bzip2.
```
snt -h localhost --secure --compression=lz4
```
Specifying a symmetric cipher algorithm. Valid options are: aesecb128, aesecb192, aesecb256, blowfish, des, 3des, aescbc128, aescbc192, aescbc256, aescfb128, aescfb192, aescfb256, aesofb128, aesofb192, aesofb256, 3descbc, bfcbc, bfcfb, rc4, cast, castcbc and castcfb.
```
snt -h localhost --secure --cipher=aescbc128
```

## Server
The server mode requires at least that the *--server* option is specified in order for the *snt* program to run in server mode.
```
snt --server --secure --compression=all --verbose
```
Set the affinity mapping that has the following format: CPU, core index, number of adjacent cores.
```
snt --server affinity=0,1,2
```

## Contributing

Please read the [CONTRIBUTING.md](CONTRIBUTING) for more details of how you can contriubute.

## Dependencies
In order to compile the program, the following *Debian* packages is required.
```
apt-get install libzip-dev liblz4-dev libssl1.0-dev libbz2-dev
```
In order to use the *system v* service, the following *Debian* package is required.
```
apt-get install daemon
```

# License
This project is licensed under the GPL+3 License - see the [LICENSE](LICENSE) file for details.
