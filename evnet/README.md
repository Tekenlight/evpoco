Context
=======

The process of making connections is a costly operation both at the server and at the client side. The TCP-3 way hand shake, together with the establishment of TLS session, are overhead if the same has to be done repeatedly. This overhead can be avoided if the opened connections can be held for long durations of time.

Holding connection for long has its own set of disadvantages;

The app server dedicates one worker thread per connection. This limits the number of connections that can be handled in a server process

In order to support many clients, it is imperative to adopt a strategy of closing the connections after processing a fixed number of requests or after certain period of time.

If connections can be held alive without causing overheads of dedicating threads and having to compromise the number of clients, it will become possible to improve the average response time of server requests.

The solution is to implement Event driven IO handling strategy for TCP server logic in Poco library.

**Design objectives**

* Use “libev” library to enable polling and event handling of the server.
* Limit the number of worker threads to a fixed number, typically equal to number of cores on which the server is running (or a small integral multiple of that)
* Achieve multiplexing at the level of client requests, as against multiplexing at the level of client connections, thus giving a more equally distributed allocation of server resources to all client requests.
* Avoid the necessity to a memcpy of request data from socket to a memory buffer and vice versa, Once a request arrives, hand over the socket to a worker thread, which will complete processing of one request and hand the socket back to the event handling thread.
* FUTURE ENHANCEMENT
	1. If more and more requests pile up, the network buffer will get filled up and the clients will not be able to send more data. This acts as a natural throttle rather than creating one in memory.
	2. This however should not limit the scalability of the server. That is to say, it should not so happen that the server resources (memory and CPU) are free, while the network buffer is full. 
	3. If this situation occurs, some mechanism of buffering incoming request data should be provided in the server, which will enable utilisation of CPU resources and higher scalability of the app server.

**Design considerations**

***Option 1:***

Enhance the existing Net component with changes to existing classes and additional classes to achieve the requirements.

***Option 2:***

Create a new component EVNet - Event driven Network library, which is an extension of the Network library.


Considering the fact that the existing Net library is free from dependency on any third party library and the proposed feature needs to make use of [libev](http://software.schmorp.de/pkg/libev.html). It is better to leave the Net component with very little changes and add a new component EVNet, which can be made optional.

