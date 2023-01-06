<img src="doc/images/logotk.png" width="250"/>


EVPOCO (EVENT DRIVEN Portable Components) C/C++ Libraries are:
---------------------------------------------

- A collection of C++ class libraries and C functions, built by enahancing [Poco library](https://github.com/pocoproject/poco)
- Exposes a set of platform functions to lua programming language, making it easy to develop web applications in lua
- Implements event driven IO through coroutines, i.e. threads initiating IO do not block and continue with other taks, and once the IO is complete any free thread continue the task from where it was left of
- The IO-event driven task handling is achieved via coroutines in lua, which accomplishes cooperative multi-tasking and provides the programmer an interface of sequential code vis-a-vis an event driven code with promises etc...
- Focused on solutions to frequently-encountered practical problems.
- Focused on ‘internet-age’ network-centric applications.
- Open Source, licensed under the [Boost Software License](https://spdx.org/licenses/BSL-1.0).

![alt text][overview]

----
To start using POCO, see the [Guided Tour](https://pocoproject.org/docs/00100-GuidedTour.html)
and [Getting Started](https://pocoproject.org/docs/00200-GettingStarted.html) documents.

----
POCO has an active user and contributing community, please visit our [web site](https://pocoproject.org) and [blog](https://pocoproject.org/blog).
Answers to POCO-related questions can also be found on [Stack Overflow](https://stackoverflow.com/questions/tagged/poco-libraries).

Please see [CONTRIBUTING](CONTRIBUTING.md) for submitting contributions, bugs reports, feature requests or security issues.

----
In regards to Boost, in spite of some functional overlapping,
POCO is best thought of as a Boost complement (rather than replacement).
Side-by-side use of Boost and POCO is a very common occurrence.

[overview]: doc/images/Overview.png "evpoco Overview"
