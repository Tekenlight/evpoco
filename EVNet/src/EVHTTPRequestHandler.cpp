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


#include <fcntl.h>

#include "Poco/EVNet/EVHTTPRequestHandler.h"
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

long EVHTTPRequestHandler::closeHTTPSession(EVHTTPClientSession* sess)
{
	Poco::EVNet::EVServer & server = getServer();
	long sr_num = 0;

	SRData * srdata = new SRData();
	srdata->addr = sess->getAddr();
	srdata->session_ptr = sess;
	srdata->cb_evid_num = HTTP_CONNECTION_CLOSED;

	//DEBUGPOINT("Here Host empty = %d, bypass = %d\n", (int)proxyConfig().host.empty(), (int)bypassProxy(addr.host().toString()));
	if (proxyConfig().host.empty() || bypassProxy(sess->getAddr().host().toString())) {
		sr_num = server.submitRequestForClose(HTTP_CONNECTION_CLOSED, getAccSockfd(), sess->getSS());
	}
	else {
		// TBD : Connect to proxy server first over here. TBD
		// Set callback to HTTP_CONNECT_PROXYSOCK_READY here
	}

	_srColl[sr_num] = srdata;

	return sr_num;
}

long EVHTTPRequestHandler::makeNewHTTPConnection(int cb_evid_num, EVHTTPClientSession* sess)
{
	Poco::EVNet::EVServer & server = getServer();
	long sr_num = 0;

	if (sess->getState() != EVHTTPClientSession::NOT_CONNECTED) {
		return -1;
	}

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

/* This method assumes that input HTTPRequest is completely formed. */
long EVHTTPRequestHandler::sendHTTPRequestData(EVHTTPClientSession *sess)
{
	if (fcntl(sess->getSS().impl()->sockfd(), F_GETFD) < 0) return -1;
	return 0;
}

bool EVHTTPRequestHandler::bypassProxy(std::string host)
{
	if (!proxyConfig().nonProxyHosts.empty()) {
		return RegularExpression::match(host, proxyConfig().nonProxyHosts, RegularExpression::RE_CASELESS | RegularExpression::RE_ANCHORED);
	}
	else return false;
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
	bool continue_event_loop = false;
	long sr_num = _usN->getSRNum();

	/* If this Service request was not created here
	 * no action needs to be taken here.
	 * */
	if (!_srColl[sr_num]) return PROCESSING;

	//DEBUGPOINT("Here\n");
	switch (getEvent()) {
		case HTTP_CONNECT_SOCK_READY:
			//DEBUGPOINT("Here\n");
			if ((_usN->getBytes() < 0) || _usN->getErrNo()) {
				_usN->setCBEVIDNum((_srColl[sr_num])->cb_evid_num);
				_srColl[sr_num]->session_ptr->setState(EVHTTPClientSession::ERROR);
			}
			else {
				//DEBUGPOINT("Here\n");
				/* No proxy or it has to be bypassed. */
				
				_usN->setCBEVIDNum((_srColl[sr_num])->cb_evid_num);
				_srColl[sr_num]->session_ptr->setState(EVHTTPClientSession::CONNECTED);
			}
			break;
		case HTTP_CONNECT_PROXYSOCK_READY:
			// TBD: Handle connecting through the proxy here. TBD
			/* Send CONNECT request to proxy server, setting callback
			 * event as HTTP_CONNECT_RSP_FROM_PROXY.
			 * The event handling of HTTP_CONNECT_RSP_FROM_PROXY should be
			 * coded in a reentrant manner.
			 * */
			break;
		case HTTP_CONNECTION_CLOSED:
			continue_event_loop = true;
			_srColl.erase(sr_num);
			break;
		case HTTP_CONNECT_RSP_FROM_PROXY:
		default:
			break;
	}

	if (continue_event_loop) {
		ret = PROCESSING;
	}
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
