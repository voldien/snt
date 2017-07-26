# snt #
----
*snt* - simple-network-tool is a network tool for performing network performance tests. The program supports multiple benchmark modes for testing various aspect of the network. The benchmark can use compression and encryption optionally in order to check how encryption and compression will change the network performance.

The *snt* program uses the server/client connection model. Where the server and client is executed on the same executable binary.

*Benchmark modes*

* Performance - Send as much data as possible.
* Integrity - Sends a number sequence or time stamp to compare the arrival in order to check if they arrived in a consecutive order or not.
* File-Transfer - Send a file, used for repeatable benchmark testing when using encryption and compression.


## Motivation
----
This project was created for educational purposes. It was created in order learn about creating a secure connection with asymmetric and symmetric ciphers.


# Installation #
----
The program is installed with the following commands.
```
make
make install
```
#wireshark#
The wireshark dissector for decoding snt packets with wireshark program can be installed with the following command:
```
make install_wireshark
```
This will install a lua script in the $(USER)/.wireshark.

#service#
service script can be installed to run the snt program as a service. This can be done with the following command:
```bash
make insall_service 
```
The the service can be started as followed:
```bash
service sntd start
```

# Examples #
----
This section cover some examples of how to use the *snt* program. See *snt*(1) for what command line options are available.

## Client ##
Running in client mode requires at least the *-h* option with the  hostname or IP address argument of the server that it shall connect to in order to work. The *snt* program is by default running as a client.
```
snt -h localhost --secure --compression -b performance --verbose
```
## Server ##
The server mode requires at least that the *--server* is specified in order for the *snt* program to run in server mode.
```
snt --server --secure --compression=all --verbose
```


## Dependencies ##
----------------
In order to compile the program, the following Debian packages has to be installed.
```
apt-get install libzip-dev liblz4-dev libssl-dev libbz2-dev
```
In order to use the service, the following Debian package has to be installed.
```
apt-get install daemon
```

## License ##

This project is licensed under the GPL+3 License - see the [LICENSE](LICENSE) file for details