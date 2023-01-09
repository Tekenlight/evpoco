<img src="doc/images/logotk.png" width="200"/>


EVPOCO (EVENT DRIVEN Portable Components) C/C++ Libraries are:
---------------------------------------------

Provides a cooperative multitasking platform fr LUA

<img src="doc/images/LUA_THREADS.png" width="200"/>

- A collection of C++ class libraries and C functions, built by enahancing a fork from [Poco library](https://github.com/pocoproject/poco)
- Exposes a set of platform functions to lua programming language, making it easy to develop web applications in lua
- Implements event driven IO through coroutines, i.e. threads initiating IO do not block and continue with other taks, and once the IO is complete any available thread continues the task from where the task was left of
- The IO-event driven task handling is achieved via coroutines in lua, which accomplishes cooperative multi-tasking and provides the programmer an interface of sequential code vis-a-vis an event driven code with promises etc...
- Focused on solutions to frequently-encountered practical problems.
- Focused on ‘internet-age’ network-centric applications.
- Open Source, licensed under the [Boost Software License](https://spdx.org/licenses/BSL-1.0).

![alt text][overview]

The library essentially genetates two outputs evluaserver and evlua
- **evluaserver**: A HTTP server that listens on a port for HTTP requests. Upon arrival of a new HTTP request a lua file main.lua is run. The file should be present in the directory where from where the executable is run or present in path as specified by the environmental variable EVLUA_PATH
	- The global lua module **platform** is avaialble to the lua file using which other aspects of HTTP processing such as request, response etc... can be accessed. The [documentation](https://github.com/Tekenlight/evpoco/wiki) has complete datails of various services available to the lua environment.
- **evlua**: A standalone component which can run a lua script from the commandline. A lua file when run from evlua can access **platform** and achieve event driven IO.

Build and dependencies:
---------------------------------------------

- CMake 3.5 or newer
- A C++14 compiler (GCC 5.0, Clang 3.4, or newer)
- OpenSSL headers and libraries
- PostgreSQL client libraries  
- openssl and libssl-dev

Dependencies maintained in Tekenlight
- [Customized libev](https://github.com/Tekenlight/libev)
- [Customized lua 5.3.5](https://github.com/Tekenlight/lua)
- [efio event driven file-io and lockfree data structures](https://github.com/Tekenlight/efio)
- [Customized redis client](https://github.com/Tekenlight/hiredis)

Currently the dependencies maintained in Tekenlight have to be built first and installed before building evpoco.
(TDB) Customized libev, Customized lua 5.3.5 and efio are to be merged into the evpoco repository

Building with CMake (linux and MacOS):
-------
```
$ git clone -b master https://github.com/Tekenlight/evpoco  
$ cd evpoco  
$ mkdir cmake-build  
$ cmake -DPG_VERSION="<Postgresql version 12 or 14>" ..  
$ cmake --build . --config Release  
```

Usage [examples](https://github.com/Tekenlight/evpoco/tree/master/evluaserver/samples/LUA/src) of evlua and evluaserver are provided

----
See the [documentation](https://github.com/Tekenlight/evpoco/wiki) for usage

[overview]: doc/images/Overview.png "evpoco Overview"
