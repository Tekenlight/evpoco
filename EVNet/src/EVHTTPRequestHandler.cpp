//
// EVHTTPRequestHandler.cpp
//
// Library: EVNet
// Package: EVHTTPServer
// Module:  EVHTTPRequestHandler
//
// Copyright (c) 2019-2020, Tekenlight Solutions Pvt Ltd
//
//


#include "Poco/EVNet/EVHTTPRequestHandler.h"
#include "Poco/EVNet/EVConnectedStreamSocket.h"
#include "Poco/Net/HTTPClientSession.h"
#include "Poco/RegularExpression.h"


namespace Poco {
namespace EVNet {


EVHTTPRequestHandler::EVHTTPRequestHandler():
	_state(INITIAL)
{
}


EVHTTPRequestHandler::~EVHTTPRequestHandler()
{
    for ( SRColMapType::iterator it = _srColl.begin(); it != _srColl.end(); ++it ) {
        delete it->second;
    }
    _srColl.clear();
}

int EVHTTPRequestHandler::getState()
{
	return _state;
}

void EVHTTPRequestHandler::setState(int state)
{
	_state = state;
}

long EVHTTPRequestHandler::makeNewSocketConnection(int cb_evid_num, Net::SocketAddress& addr, Net::StreamSocket& css)
{
	Poco::EVNet::EVServer & server = getServer();
	long sr_num = 0;
	SRData * srdata = new SRData();

	srdata->addr = addr;
	srdata->cb_evid_num = cb_evid_num;

	srdata->addr = addr;
	srdata->cb_evid_num = cb_evid_num;

	sr_num = server.submitRequestForConnection(cb_evid_num, getAccSockfd(), addr, css);

	_srColl[sr_num] = srdata;

	DEBUGPOINT("Service Request Number = %ld\n", sr_num);
	return sr_num;
}

long EVHTTPRequestHandler::makeNewHTTPConnection(int cb_evid_num, EVHTTPClientSession* sess)
{
	Poco::EVNet::EVServer & server = getServer();
	long sr_num = 0;

	SRData * srdata = new SRData();
	srdata->addr = sess->getAddr();
	srdata->session_ptr = sess;
	srdata->cb_evid_num = cb_evid_num;

	//DEBUGPOINT("Here Host empty = %d, bypass = %d\n", (int)proxyConfig().host.empty(), (int)bypassProxy(addr.host().toString()));
	if (proxyConfig().host.empty() || bypassProxy(sess->getAddr().host().toString())) {
		sr_num = server.submitRequestForConnection(HTTP_CONNECT_SOCK_READY, getAccSockfd(), sess->getAddr(), sess->getSS());
	}
	else {
		// TBD : Connect to proxy server first over here. TBD
		// Set callback to HTTP_CONNECT_PROXYSOCK_READY here
	}

	_srColl[sr_num] = srdata;

	return sr_num;
}

bool EVHTTPRequestHandler::bypassProxy(std::string host)
{
	if (!proxyConfig().nonProxyHosts.empty()) {
		return RegularExpression::match(host, proxyConfig().nonProxyHosts, RegularExpression::RE_CASELESS | RegularExpression::RE_ANCHORED);
	}
	else return false;
}

StreamSocket& EVHTTPRequestHandler::getConnSS(poco_socket_t fd)
{
	EVProcessingState & procState = getProcState();
	EVConnectedStreamSocket & cn = procState.getEVConnSock(fd);

	return cn.getStreamSocket();
}

int EVHTTPRequestHandler::handleRequestSurrogateInitial()
{
	int ret = 0;
	try {
		ret = handleRequest();
	}
	catch (...) {
		ret = PROCESSING_ERROR;
	}

	return ret;
}

int EVHTTPRequestHandler::handleRequestSurrogate()
{
	int ret = 0;
	bool continue_event_loop = true;
	long sr_num = _usN->getSRNum();

	//DEBUGPOINT("Here\n");
	switch (getEvent()) {
		case HTTP_CONNECT_SOCK_READY:
			//DEBUGPOINT("Here\n");
			if ((_usN->getBytes() < 0) || _usN->getErrNo()) {
				//DEBUGPOINT("Here\n");
				_usN->setCBEVIDNum((_srColl[sr_num])->cb_evid_num);
			}
			else {
				Net::SocketAddress addr = getConnSS(_usN->sockfd()).address();
				//DEBUGPOINT("Here\n");
				/* No proxy or it has to be bypassed. */
				_usN->setCBEVIDNum((_srColl[sr_num])->cb_evid_num);
			}
			continue_event_loop = false;
			break;
		case HTTP_CONNECT_PROXYSOCK_READY:
			// TBD: Handle connecting through the proxy here. TBD
			/* Send CONNECT request to proxy server, setting callback
			 * event as HTTP_CONNECT_RSP_FROM_PROXY.
			 * The event handling of HTTP_CONNECT_RSP_FROM_PROXY should be
			 * coded in a reentrant manner.
			 * */
			break;
		case HTTP_CONNECT_RSP_FROM_PROXY:
		default:
			continue_event_loop = false;
			break;
	}

	if (continue_event_loop) { ret = PROCESSING; }
	else {
		try {
			ret = handleRequest();
		}
		catch (...) {
			ret = PROCESSING_ERROR;
		}
		_srColl.erase(sr_num);
	}

	return ret;
}

} } // namespace Poco::EVNet
