//
// EVHTTPRequestHandler.h
//
// Library: EVNet
// Package: EVHTTPServer
// Module:  EVHTTPRequestHandler
//
// Definition of the EVHTTPRequestHandler class.
//
// Copyright (c) 2019-2020, Tekenlight Solutions Pvt Ltd
// and Contributors.
//
//


#ifndef Net_EVHTTPRequestHandler_INCLUDED
#define Net_EVHTTPRequestHandler_INCLUDED


#include "Poco/Net/Net.h"
#include "Poco/Net/HTTPRequestHandler.h"
#include "Poco/EVNet/EVNet.h"
#include "Poco/EVNet/EVUpstreamEventNotification.h"
#include "Poco/EVNet/EVServer.h"
#include "Poco/EVNet/EVProcessingState.h"


namespace Poco {
namespace EVNet {

class Net_API EVHTTPRequestHandler
	/// The abstract base class for EVHTTPRequestHandlers 
	/// created by EVHTTPServer.
	///
	/// Derived classes must override the handleRequest() method.
	/// Furthermore, a EVHTTPRequestHandlerFactory must be provided.
	///
	/// The handleRequest() method must perform the complete handling
	/// of the HTTP request connection. As soon as the handleRequest() 
	/// method returns, the request handler object is destroyed.
	///
	/// A new EVHTTPRequestHandler object will be created for
	/// each new HTTP request that is received by the HTTPServer.
{
public:
	typedef std::map<long,int *> SRColMapType;
	static const int INITIAL = 0;

	/* Return values of handleRequest method. */
	static const int PROCESSING_ERROR = -1;
	static const int PROCESSING = 0;
	static const int PROCESSING_COMPLETE = 1;

	EVHTTPRequestHandler();
		/// Creates the EVHTTPRequestHandler.

	virtual ~EVHTTPRequestHandler();
		/// Destroys the EVHTTPRequestHandler.

	virtual int handleRequest() = 0;
		/// Must be overridden by subclasses.
		///
		/// Handles the given request.

	int handleRequestSurrogate();

	int getState();
	void setState(int);
	EVUpstreamEventNotification & getUNotification();
	void setUNotification(EVUpstreamEventNotification *);
	int getEvent();
	EVServer& getServer();
	void setServer(EVServer * server);
	poco_socket_t getAccSockfd();
	void setAccSockfd(poco_socket_t fd);
	Net::HTTPServerRequest& getRequest();
	void setRequest(Net::HTTPServerRequest* req);
	Net::HTTPServerResponse& getResponse();
	void setResponse(Net::HTTPServerResponse* res);
	void setProcState(EVProcessingState* reqProcState);
	EVProcessingState& getProcState();
	long makeNewSocketConnection(int cb_evid_num, Net::SocketAddress& addr, Net::StreamSocket& css);
	long makeNewHTTPConnection(int cb_evid_num, Net::SocketAddress& addr, Net::StreamSocket& css);

private:
	EVHTTPRequestHandler(const EVHTTPRequestHandler&);
	EVHTTPRequestHandler& operator = (const EVHTTPRequestHandler&);

	int								_state;
	EVUpstreamEventNotification*	_usN;
	EVServer*						_server;
	poco_socket_t					_acc_fd;
	Net::HTTPServerRequest*			_req = NULL;
	Net::HTTPServerResponse*		_rsp = NULL;
	EVProcessingState*				_reqProcState;
	SRColMapType					_srColl;
};

inline EVUpstreamEventNotification & EVHTTPRequestHandler::getUNotification()
{
	return *_usN;
}

inline void EVHTTPRequestHandler::setUNotification(EVUpstreamEventNotification * usN)
{
	_usN = usN;
}

inline int EVHTTPRequestHandler::getEvent()
{
	int event = getState();
	if (!_usN || INITIAL == event) return INITIAL;

	return _usN->getCBEVIDNum();
}

inline EVServer& EVHTTPRequestHandler::getServer()
{
	return *_server;
}

inline void EVHTTPRequestHandler::setServer(EVServer * server)
{
	_server = server;
}

inline poco_socket_t EVHTTPRequestHandler::getAccSockfd()
{
	return _acc_fd;
}

inline void EVHTTPRequestHandler::setAccSockfd(poco_socket_t fd)
{
	_acc_fd = fd;
}

inline Net::HTTPServerRequest& EVHTTPRequestHandler::getRequest()
{
	return *_req;
}

inline void EVHTTPRequestHandler::setRequest(Net::HTTPServerRequest* req)
{
	_req = req;
}

inline Net::HTTPServerResponse& EVHTTPRequestHandler::getResponse()
{
	return *_rsp;
}

inline void EVHTTPRequestHandler::setResponse(Net::HTTPServerResponse* rsp)
{
	_rsp = rsp;
}

inline void EVHTTPRequestHandler::setProcState(EVProcessingState* reqProcState)
{
	_reqProcState = reqProcState;
}

inline EVProcessingState& EVHTTPRequestHandler::getProcState()
{
	return *_reqProcState;
}


} } // namespace Poco::EVNet


#endif // Net_EVHTTPRequestHandler_INCLUDED
