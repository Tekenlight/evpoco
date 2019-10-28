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

long EVHTTPRequestHandler::makeNewSocketConnection(TCallback cb, Net::SocketAddress& addr, Net::StreamSocket& css)
{
	Poco::EVNet::EVServer & server = getServer();
	long sr_num = 0;
	SRData * srdata = new SRData();

	srdata->addr = addr;
	srdata->cb_evid_num = HTTPRH_CALL_CB_HANDLER;
	srdata->cb = cb;
	sr_num = server.submitRequestForConnection(HTTPRH_CALL_CB_HANDLER, getAccSockfd(), addr, css);

	_srColl[sr_num] = srdata;

	DEBUGPOINT("Service Request Number = %ld\n", sr_num);
	return sr_num;
}

long EVHTTPRequestHandler::makeNewSocketConnection(EventHandler& cb_handler, Net::SocketAddress& addr, Net::StreamSocket& css)
{
	Poco::EVNet::EVServer & server = getServer();
	long sr_num = 0;
	SRData * srdata = new SRData();

	srdata->addr = addr;
	srdata->cb_handler = &cb_handler;
	srdata->cb_evid_num = HTTPRH_INVALID_CB_NUM;
	sr_num = server.submitRequestForConnection(HTTPRH_CALL_CB_HANDLER, getAccSockfd(), addr, css);

	_srColl[sr_num] = srdata;

	DEBUGPOINT("Service Request Number = %ld\n", sr_num);
	return sr_num;
}

long EVHTTPRequestHandler::makeNewSocketConnection(int cb_evid_num, Net::SocketAddress& addr, Net::StreamSocket& css)
{
	Poco::EVNet::EVServer & server = getServer();
	long sr_num = 0;
	SRData * srdata = new SRData();

	srdata->addr = addr;
	srdata->cb_evid_num = cb_evid_num;

	sr_num = server.submitRequestForConnection(cb_evid_num, getAccSockfd(), addr, css);

	_srColl[sr_num] = srdata;

	DEBUGPOINT("Service Request Number = %ld\n", sr_num);
	return sr_num;
}

long EVHTTPRequestHandler::closeHTTPSession(EVHTTPClientSession* sess)
{
	getServer().submitRequestForClose(getAccSockfd(), sess->getSS());
	return 0;
}

long EVHTTPRequestHandler::makeNewHTTPConnection(int cb_evid_num, EVHTTPClientSession* sess)
{
	Poco::EVNet::EVServer & server = getServer();
	long sr_num = 0;

	if (sess->getState() != EVHTTPClientSession::NOT_CONNECTED) {
		return -1;
	}

	sess->setAccfd(getAccSockfd());

	SRData * srdata = new SRData();
	srdata->addr = sess->getAddr();
	srdata->session_ptr = sess;
	srdata->cb_evid_num = cb_evid_num;

	//DEBUGPOINT("Here Host empty = %d, bypass = %d\n", (int)proxyConfig().host.empty(), (int)bypassProxy(addr.host().toString()));
	if (proxyConfig().host.empty() || bypassProxy(sess->getAddr().host().toString())) {
		sr_num = server.submitRequestForConnection(HTTPRH_CONNECT_SOCK_READY, getAccSockfd(), sess->getAddr(), sess->getSS());
	}
	else {
		// TBD : Connect to proxy server first over here. TBD
		// Set callback to HTTPRH_CONNECT_PROXYSOCK_READY here
	}

	_srColl[sr_num] = srdata;

	return sr_num;
}

long EVHTTPRequestHandler::makeNewHTTPConnection(TCallback cb, EVHTTPClientSession* sess)
{
	Poco::EVNet::EVServer & server = getServer();
	long sr_num = 0;

	if (sess->getState() != EVHTTPClientSession::NOT_CONNECTED) {
		return -1;
	}

	sess->setAccfd(getAccSockfd());

	SRData * srdata = new SRData();
	srdata->addr = sess->getAddr();
	srdata->session_ptr = sess;
	srdata->cb_evid_num = HTTPRH_CALL_CB_HANDLER;
	srdata->cb = cb;

	//DEBUGPOINT("Here Host empty = %d, bypass = %d\n", (int)proxyConfig().host.empty(), (int)bypassProxy(addr.host().toString()));
	if (proxyConfig().host.empty() || bypassProxy(sess->getAddr().host().toString())) {
		sr_num = server.submitRequestForConnection(HTTPRH_CONNECT_SOCK_READY, getAccSockfd(), sess->getAddr(), sess->getSS());
	}
	else {
		// TBD : Connect to proxy server first over here. TBD
		// Set callback to HTTPRH_CONNECT_PROXYSOCK_READY here
	}

	_srColl[sr_num] = srdata;

	return sr_num;
}

long EVHTTPRequestHandler::makeNewHTTPConnection(EventHandler& cb_handler, EVHTTPClientSession* sess)
{
	Poco::EVNet::EVServer & server = getServer();
	long sr_num = 0;

	if (sess->getState() != EVHTTPClientSession::NOT_CONNECTED) {
		return -1;
	}

	sess->setAccfd(getAccSockfd());

	SRData * srdata = new SRData();
	srdata->addr = sess->getAddr();
	srdata->session_ptr = sess;
	srdata->cb_evid_num = HTTPRH_INVALID_CB_NUM;
	srdata->cb_handler = &cb_handler;

	//DEBUGPOINT("Here Host empty = %d, bypass = %d\n", (int)proxyConfig().host.empty(), (int)bypassProxy(addr.host().toString()));
	if (proxyConfig().host.empty() || bypassProxy(sess->getAddr().host().toString())) {
		sr_num = server.submitRequestForConnection(HTTPRH_CONNECT_SOCK_READY, getAccSockfd(), sess->getAddr(), sess->getSS());
	}
	else {
		// TBD : Connect to proxy server first over here. TBD
		// Set callback to HTTPRH_CONNECT_PROXYSOCK_READY here
	}

	_srColl[sr_num] = srdata;

	return sr_num;
}

long EVHTTPRequestHandler::waitForHTTPResponse(int cb_evid_num, EVHTTPClientSession* sess, EVHTTPResponse& res)
{
	Poco::EVNet::EVServer & server = getServer();
	long sr_num = 0;

	if (sess->getState() != EVHTTPClientSession::CONNECTED) return -1;
	if (fcntl(sess->getSS().impl()->sockfd(), F_GETFD) < 0) return -1;

	SRData * srdata = new SRData();
	srdata->addr = sess->getAddr();
	srdata->session_ptr = sess;
	srdata->cb_evid_num = cb_evid_num;
	srdata->response = &res;

	sr_num = server.submitRequestForRecvData(HTTPRH_RESP_MSG_FROM_HOST, getAccSockfd(), sess->getSS());

	_srColl[sr_num] = srdata;

	return sr_num;
}

long EVHTTPRequestHandler::waitForHTTPResponse(TCallback cb, EVHTTPClientSession* sess, EVHTTPResponse& res)
{
	Poco::EVNet::EVServer & server = getServer();
	long sr_num = 0;

	if (sess->getState() != EVHTTPClientSession::CONNECTED) return -1;
	if (fcntl(sess->getSS().impl()->sockfd(), F_GETFD) < 0) return -1;

	SRData * srdata = new SRData();
	srdata->addr = sess->getAddr();
	srdata->session_ptr = sess;
	srdata->cb_evid_num = HTTPRH_CALL_CB_HANDLER;
	srdata->cb = cb;
	srdata->response = &res;

	sr_num = server.submitRequestForRecvData(HTTPRH_RESP_MSG_FROM_HOST, getAccSockfd(), sess->getSS());

	_srColl[sr_num] = srdata;

	return sr_num;
}

long EVHTTPRequestHandler::waitForHTTPResponse(EventHandler& cb_handler, EVHTTPClientSession* sess, EVHTTPResponse& res)
{
	Poco::EVNet::EVServer & server = getServer();
	long sr_num = 0;

	if (sess->getState() != EVHTTPClientSession::CONNECTED) return -1;
	if (fcntl(sess->getSS().impl()->sockfd(), F_GETFD) < 0) return -1;

	SRData * srdata = new SRData();
	srdata->addr = sess->getAddr();
	srdata->session_ptr = sess;
	srdata->cb_evid_num = HTTPRH_CALL_CB_HANDLER;
	srdata->cb_handler = &cb_handler;
	srdata->response = &res;

	sr_num = server.submitRequestForRecvData(HTTPRH_RESP_MSG_FROM_HOST, getAccSockfd(), sess->getSS());

	_srColl[sr_num] = srdata;

	return sr_num;
}

long EVHTTPRequestHandler::sendHTTPHeader(EVHTTPClientSession &sess, EVHTTPRequest &req)
{
	if (sess.getState() != EVHTTPClientSession::CONNECTED) return -1;
	if (fcntl(sess.getSS().impl()->sockfd(), F_GETFD) < 0) return -1;
	req.prepareHeaderForSend();
	sess.getSendStream()->transfer(req.getMessageHeader());
	getServer().submitRequestForSendData(getAccSockfd(), sess.getSS());

	return 0;
}

/* This method assumes that input HTTPRequest is completely formed. */
long EVHTTPRequestHandler::sendHTTPRequestData(EVHTTPClientSession &sess, EVHTTPRequest &req)
{
	if (sess.getState() != EVHTTPClientSession::CONNECTED) return -1;
	if (fcntl(sess.getSS().impl()->sockfd(), F_GETFD) < 0) return -1;
	sess.getSendStream()->transfer(req.getMessageBody());
	getServer().submitRequestForSendData(getAccSockfd(), sess.getSS());

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
	//DEBUGPOINT("Here event = %d, SRP = %p\n", getEvent(), _srColl[sr_num]);
	if (!_srColl[sr_num]) return PROCESSING;
	//DEBUGPOINT("Here event = %d, \n", getEvent());

	switch (getEvent()) {
		case HTTPRH_CONNECT_SOCK_READY:
			_usN->setCBEVIDNum((_srColl[sr_num])->cb_evid_num);
			if ((_usN->getRet() < 0) || _usN->getErrNo()) {
				_srColl[sr_num]->session_ptr->setState(EVHTTPClientSession::ERROR);
			}
			else {
				/* No proxy or it has to be bypassed. */
				_srColl[sr_num]->session_ptr->setState(EVHTTPClientSession::CONNECTED);
				_srColl[sr_num]->session_ptr->setRecvStream(_usN->getRecvStream());
				_srColl[sr_num]->session_ptr->setSendStream(_usN->getSendStream());
			}
			break;
		case HTTPRH_CONNECT_PROXYSOCK_READY:
			// TBD: Handle connecting through the proxy here. TBD
			/* Send CONNECT request to proxy server, setting callback
			 * event as HTTPRH_CONNECT_RSP_FROM_PROXY.
			 * The event handling of HTTPRH_CONNECT_RSP_FROM_PROXY should be
			 * coded in a reentrant manner.
			 * */
			break;
		case HTTPRH_RESP_MSG_FROM_HOST:
			{
				int parse_ret = 0;
				if ((_usN->getRet() < 0) || _usN->getErrNo()) {
					_srColl[sr_num]->session_ptr->setState(EVHTTPClientSession::ERROR);
					_usN->setCBEVIDNum((_srColl[sr_num])->cb_evid_num);
				}
				else {
					_srColl[sr_num]->session_ptr->setRecvStream(_usN->getRecvStream());
					_srColl[sr_num]->session_ptr->setSendStream(_usN->getSendStream());
					parse_ret = _srColl[sr_num]->session_ptr->continueRead(*(_srColl[sr_num]->response));
					if (parse_ret < 0) {
						_usN->setRet(-1);
						closeHTTPSession(_srColl[sr_num]->session_ptr);
						_usN->setCBEVIDNum((_srColl[sr_num])->cb_evid_num);
					}
					else if (parse_ret < MESSAGE_COMPLETE) {
						SRData * old = _srColl[sr_num];
						SRData * srdata = new SRData(*old);
						_srColl.erase(sr_num);
						delete old;
						Poco::EVNet::EVServer & server = getServer();
						sr_num = server.submitRequestForRecvData(HTTPRH_RESP_MSG_FROM_HOST,
											getAccSockfd(), srdata->session_ptr->getSS());
						_srColl[sr_num] = srdata;
						continue_event_loop = true;
					}
					else {
						_usN->setCBEVIDNum((_srColl[sr_num])->cb_evid_num);
					}
				}
			}
			break;
		case HTTPRH_CONNECT_RSP_FROM_PROXY:
			break;
		case HTTPRH_CALL_CB_HANDLER:
			break;
		default:
			break;
	}

	if (continue_event_loop) {
		ret = PROCESSING;
	}
	else {
		try {
			if ((_srColl[sr_num])->cb_handler) {
				ret = (*((_srColl[sr_num])->cb_handler))();
			}
			else if (0 != (_srColl[sr_num])->cb) {
				ret = (_srColl[sr_num])->cb();
			}
			else {
				ret = handleRequest();
			}
		}
		catch (...) {
			ret = PROCESSING_ERROR;
		}
		SRData * old = _srColl[sr_num];
		_srColl.erase(sr_num);
		delete old;
	}

	return (ret<0)?PROCESSING_ERROR:ret;
}

} } // namespace Poco::EVNet
