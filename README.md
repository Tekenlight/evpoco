<img src="doc/images/logotk.png" width="200"/>


EVPOCO (EVENT DRIVEN Portable Components) C/C++ Libraries are:
---------------------------------------------

- A collection of C++ class libraries and C functions, built by enahancing a fork from [Poco library](https://github.com/pocoproject/poco)
- Exposes a set of platform functions to lua programming language, making it easy to develop standalone  and web applications in lua
- Implements event driven IO through coroutines, i.e. threads initiating IO do not block and continue with other taks, and once the IO is complete any available thread continues the task from where the task was left of
- The IO-event driven task handling is achieved via coroutines in lua, which accomplishes cooperative multi-tasking and provides the programmer an interface of sequential code vis-a-vis an event driven code with promises etc...
- Focused on solutions to frequently-encountered practical problems.
- Focused on ‘internet-age’ network-centric applications.
- Open Source, licensed under the [Boost Software License](https://spdx.org/licenses/BSL-1.0).

![alt text][overview]

----
See the [documentation](https://github.com/Tekenlight/evpoco/wiki) for usage

Please see [CONTRIBUTING](CONTRIBUTING.md) for submitting contributions, bugs reports, feature requests or security issues.


[overview]: doc/images/Overview.png "evpoco Overview"
