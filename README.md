<img src="doc/images/logotk.png" width="200"/>


EVPOCO (EVENT DRIVEN Portable Components) C/C++ Libraries are:
---------------------------------------------

- A collection of C++ class libraries and C functions, built by enahancing a fork from [Poco library](https://github.com/pocoproject/poco)
- Exposes a set of platform functions to lua programming language, making it easy to develop web applications in lua
- Implements event driven IO through coroutines, i.e. threads initiating IO do not block and continue with other taks, and once the IO is complete any available thread continues the task from where the task was left of
- The IO-event driven task handling is achieved via coroutines in lua, which accomplishes cooperative multi-tasking and provides the programmer an interface of sequential code vis-a-vis an event driven code with promises etc...
- Focused on solutions to frequently-encountered practical problems.
- Focused on ‘internet-age’ network-centric applications.
- Open Source, licensed under the [Boost Software License](https://spdx.org/licenses/BSL-1.0).

![alt text][overview]

Build and dependencies:
----------------------------
- CMake 3.5 or newer
- A C++14 compiler (GCC 5.0, Clang 3.4, or newer)
- OpenSSL headers and libraries
- PostgreSQL client libraries

- openssl and libssl-dev
- [Customized libev](https://github.com/Tekenlight/libev)
- [Customized lua 5.3.5](https://github.com/Tekenlight/lua)
- [efio event driven file-io and lockfree data structures](https://github.com/Tekenlight/efio)

(TDB) Customized libev, Customized lua 5.3.5 and efio are to be merged into the evpoco repository

----
See the [documentation](https://github.com/Tekenlight/evpoco/wiki) for usage

Please see [CONTRIBUTING](CONTRIBUTING.md) for submitting contributions, bugs reports, feature requests or security issues.


[overview]: doc/images/Overview.png "evpoco Overview"
