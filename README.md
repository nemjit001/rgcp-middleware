# rgcp-middleware

This is a middleware service that allows the [RGCP library](https://github.com/nemjit001/reliable-group-communication-protocol) to work.

## Installing the middleware service

Before trying to install the RGCP middleware service, please ensure that
the RGCP library itself is already installed on your system.

To start the installation, first generate the CMake project using
the following:

```bash
$ cmake . -D CMAKE_BUILD_TYPE=Release
```

After generating the CMake project, the software can be built and installed
using the following Make command:

```bash
$ sudo make all install
```

The software is installed in the GNU install directories.

## Running the middleware service

A middleware instance can be started using the following command:

```bash
$ rgcp_middleware
```

There are several command line options available. These options allow
the configuration of the middleware service on startup. To see the
available options, `rgcp_middleware --help` can be run. This produces
the following output:

```bash
$ rgcp_middleware --help
usage: rgcp_middleware [options]
This middleware service allows RGCP sockets to interface with RGCP groups.

Available options, with defaults in [ ]:
	-p, --port		Set the port on which the middleware listens for
				connections, ranges 1~65535. [8000]
	-g, --group-timeout	Set the time it takes for an inactive group to
				expire in seconds. [60]
	-b, --heartbeat-timeout	Set the expected period for heartbeat messages received
				from clients in seconds. [5]
	-h, --help		Display this help message.

For contact info, issues, bug reports, feedback, etc., go to: www.github.com/nemjit001/rgcp-middleware
```

## Author

Tijmen Menno Verhoef
