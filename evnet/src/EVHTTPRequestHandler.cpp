//
// EVHTTPRequestHandler.cpp
//
// Library: evnet
// Package: EVHTTPServer
// Module:  EVHTTPRequestHandler
//
// Copyright (c) 2019-2020, Tekenlight Solutions Pvt Ltd
//
//


#include <fcntl.h>

#include "Poco/Net/HostEntry.h"
#include "Poco/Net/HostEntry.h"
#include "Poco/evnet/EVHTTPRequestHandler.h"
#include "Poco/RegularExpression.h"


namespace Poco {
namespace evnet {


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
	Poco::evnet::EVServer & server = getServer();
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

long EVHTTPRequestHandler::closeHTTPSession(EVHTTPClientSession& sess)
{
	sess.setState(EVHTTPClientSession::CLOSED);
	getServer().submitRequestForClose(getAccSockfd(), sess.getSS());
	return 0;
}

long EVHTTPRequestHandler::makeNewHTTPConnection(TCallback cb, EVHTTPClientSession& sess)
{
	Poco::evnet::EVServer & server = getServer();
	long sr_num = 0;

	if (sess.getState() != EVHTTPClientSession::NOT_CONNECTED) {
		return -1;
	}

	sess.setAccfd(getAccSockfd());

	SRData * srdata = new SRData();
	srdata->addr = sess.getAddr();
	srdata->session_ptr = &sess;
	srdata->cb_evid_num = HTTPRH_CALL_CB_HANDLER;
	srdata->cb = cb;

	//DEBUGPOINT("Here Host empty = %d, bypass = %d\n", (int)proxyConfig().host.empty(), (int)bypassProxy(addr.host().toString()));
	if (proxyConfig().host.empty() || bypassProxy(sess.getAddr().host().toString())) {
		sr_num = server.submitRequestForConnection(HTTPRH_HTTPCONN_CONNECTION_ESTABLISHED, getAccSockfd(), sess.getAddr(), sess.getSS());
	}
	else {
		// TBD : Connect to proxy server first over here. TBD
		// Set callback to HTTPRH_HTTPCONN_PROXYSOCK_READY here
	}

	_srColl[sr_num] = srdata;

	return sr_num;
}

long EVHTTPRequestHandler::makeNewHTTPConnection(TCallback cb,
					const char * domain_name, const unsigned short port_num, EVHTTPClientSession& sess)
{
	Poco::evnet::EVServer & server = getServer();
	long sr_num = 0;

	if (sess.getState() != EVHTTPClientSession::NOT_CONNECTED) {
		return -1;
	}

	sess.setAccfd(getAccSockfd());

	SRData * srdata = new SRData();
	srdata->session_ptr = NULL;
	srdata->cb_evid_num = HTTPRH_HTTPCONN_HOSTRESOLVED;
	srdata->cb = cb;
	srdata->domain_name = domain_name;
	srdata->serv_name = NULL;
	srdata->port_num = port_num;
	srdata->session_ptr = &sess;

	sr_num =  getServer().submitRequestForHostResolution(HTTPRH_HTTPCONN_HOSTRESOLVED, getAccSockfd(), domain_name, NULL);

	_srColl[sr_num] = srdata;

	return sr_num;
}

long EVHTTPRequestHandler::makeNewHTTPConnection(TCallback cb,
					const char * domain_name, const char * serv_name, EVHTTPClientSession& sess)
{
	Poco::evnet::EVServer & server = getServer();
	long sr_num = 0;

	if (sess.getState() != EVHTTPClientSession::NOT_CONNECTED) {
		return -1;
	}

	sess.setAccfd(getAccSockfd());

	SRData * srdata = new SRData();
	srdata->session_ptr = NULL;
	srdata->cb_evid_num = HTTPRH_HTTPCONN_HOSTRESOLVED;
	srdata->cb = cb;
	srdata->domain_name = domain_name;
	srdata->serv_name = serv_name;
	srdata->port_num = -1;
	srdata->session_ptr = &sess;

	sr_num =  getServer().submitRequestForHostResolution(HTTPRH_HTTPCONN_HOSTRESOLVED, getAccSockfd(), domain_name, serv_name);

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

long EVHTTPRequestHandler::waitForHTTPResponse(TCallback cb, EVHTTPClientSession& sess, EVHTTPResponse& res)
{
	Poco::evnet::EVServer & server = getServer();
	long sr_num = 0;

	if (sess.getState() != EVHTTPClientSession::CONNECTED) return -1;
	if (fcntl(sess.getSS().impl()->sockfd(), F_GETFD) < 0) return -1;

	SRData * srdata = new SRData();
	srdata->addr = sess.getAddr();
	srdata->session_ptr = &sess;
	srdata->cb_evid_num = HTTPRH_CALL_CB_HANDLER;
	srdata->cb = cb;
	srdata->response = &res;

	sr_num = server.submitRequestForRecvData(HTTPRH_HTTPRESP_MSG_FROM_HOST, getAccSockfd(), sess.getSS());

	_srColl[sr_num] = srdata;

	return sr_num;
}

long EVHTTPRequestHandler::resolveHost(TCallback cb,
						const char* domain_name, const char* serv_name, struct addrinfo ** addr_info_ptr_ptr)
{
	Poco::evnet::EVServer & server = getServer();
	long sr_num = 0;

	SRData * srdata = new SRData();
	srdata->cb_evid_num = HTTPRH_DNSR_HOST_RESOLUTION_DONE;
	srdata->cb = cb;
	srdata->addr_info_ptr_ptr = addr_info_ptr_ptr;

	sr_num =  getServer().submitRequestForHostResolution(HTTPRH_DNSR_HOST_RESOLUTION_DONE, getAccSockfd(), domain_name, serv_name);
	_srColl[sr_num] = srdata;

	return sr_num;
}

void EVHTTPRequestHandler::executeGenericTaskNR(generic_task_handler_nr_t tf, void * input_data)
{
	//DEBUGPOINT("Here\n");
	Poco::evnet::EVServer & server = getServer();
	server.submitRequestForTaskExecutionNR(tf, input_data);

	return ;
}

void EVHTTPRequestHandler::executeGenericTaskNR(Poco::evnet::EVServer & server, generic_task_handler_nr_t tf, void * input_data)
{
	//DEBUGPOINT("Here\n");
	server.submitRequestForTaskExecutionNR(tf, input_data);

	return ;
}

long EVHTTPRequestHandler::executeGenericTask(TCallback cb, generic_task_handler_t tf, void * input_data)
{
	Poco::evnet::EVServer & server = getServer();
	long sr_num = 0;

	SRData * srdata = new SRData();
	srdata->cb_evid_num = HTTPRH_CALL_CB_HANDLER;
	srdata->cb = cb;

	//DEBUGPOINT("Here\n");
	sr_num =  getServer().submitRequestForTaskExecution(HTTPRH_CALL_CB_HANDLER, getAccSockfd(), tf, input_data);
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
		case HTTPRH_HTTPCONN_CONNECTION_ESTABLISHED:
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
		case HTTPRH_HTTPCONN_PROXYSOCK_READY:
			// TBD: Handle connecting through the proxy here. TBD
			/* Send CONNECT request to proxy server, setting callback
			 * event as HTTPRH_HTTPCONN_PROXY_RESPONSE.
			 * The event handling of HTTPRH_HTTPCONN_PROXY_RESPONSE should be
			 * coded in a reentrant manner.
			 * */
			break;
		case HTTPRH_HTTPRESP_MSG_FROM_HOST:
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
						closeHTTPSession(*(_srColl[sr_num]->session_ptr));
						_usN->setCBEVIDNum((_srColl[sr_num])->cb_evid_num);
					}
					else if (parse_ret < MESSAGE_COMPLETE) {
						SRData * old = _srColl[sr_num];
						SRData * srdata = new SRData(*old);
						_srColl.erase(sr_num);
						delete old;
						Poco::evnet::EVServer & server = getServer();
						sr_num = server.submitRequestForRecvData(HTTPRH_HTTPRESP_MSG_FROM_HOST,
											getAccSockfd(), srdata->session_ptr->getSS());
						_srColl[sr_num] = srdata;
						continue_event_loop = true;
					}
					else {
						if (!(_srColl[sr_num]->response->getVersion().compare("HTTP/1.0"))) {
							//DEBUGPOINT("Got a response of version 1.0\n");
							closeHTTPSession(*(_srColl[sr_num]->session_ptr));
						}
						_usN->setCBEVIDNum((_srColl[sr_num])->cb_evid_num);
					}
				}
			}
			break;
		case HTTPRH_HTTPCONN_HOSTRESOLVED:
			{
				if ((_usN->getRet() < 0) || _usN->getErrNo()) {
					_srColl[sr_num]->session_ptr->setState(EVHTTPClientSession::ERROR);
					_usN->setCBEVIDNum((_srColl[sr_num])->cb_evid_num);
				}
				else {
					SRData * old = _srColl[sr_num];
					SRData * srdata = new SRData(*old);
					_srColl.erase(sr_num);
					delete old;
					Net::HostEntry he(_usN->getAddrInfo());
					Net::SocketAddress a(srdata->domain_name, he, srdata->port_num);
					srdata->addr = a;
					srdata->session_ptr->setAddr(a);
					Poco::evnet::EVServer & server = getServer();
					if (proxyConfig().host.empty() || bypassProxy(srdata->session_ptr->getAddr().host().toString())) {

						sr_num = server.submitRequestForConnection(HTTPRH_HTTPCONN_CONNECTION_ESTABLISHED,
									getAccSockfd(), srdata->session_ptr->getAddr(), srdata->session_ptr->getSS());
					}
					else {
						// TBD : Connect to proxy server first over here. TBD
						// Set callback to HTTPRH_HTTPCONN_PROXYSOCK_READY here
					}
					_srColl[sr_num] = srdata;
					continue_event_loop = true;
				}
			}
			break;
		case HTTPRH_HTTPCONN_PROXY_RESPONSE:
			break;
		case HTTPRH_DNSR_HOST_RESOLUTION_DONE:
			*(_srColl[sr_num]->addr_info_ptr_ptr) = _usN->getAddrInfo();
			break;
		case HTTPRH_CALL_CB_HANDLER:
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

/* Not useful code
long EVHTTPRequestHandler::makeNewSocketConnection(EventHandler& cb_handler, Net::SocketAddress& addr, Net::StreamSocket& css)
{
	Poco::evnet::EVServer & server = getServer();
	long sr_num = 0;
	SRData * srdata = new SRData();

	srdata->addr = addr;
	srdata->cb_handler = &cb_handler;
	srdata->cb_evid_num = HTTPRH_CALL_CB_HANDLER;
	sr_num = server.submitRequestForConnection(HTTPRH_CALL_CB_HANDLER, getAccSockfd(), addr, css);

	_srColl[sr_num] = srdata;

	DEBUGPOINT("Service Request Number = %ld\n", sr_num);
	return sr_num;
}

long EVHTTPRequestHandler::makeNewSocketConnection(int cb_evid_num, Net::SocketAddress& addr, Net::StreamSocket& css)
{
	Poco::evnet::EVServer & server = getServer();
	long sr_num = 0;
	SRData * srdata = new SRData();

	srdata->addr = addr;
	srdata->cb_evid_num = cb_evid_num;

	sr_num = server.submitRequestForConnection(cb_evid_num, getAccSockfd(), addr, css);

	_srColl[sr_num] = srdata;

	DEBUGPOINT("Service Request Number = %ld\n", sr_num);
	return sr_num;
}

long EVHTTPRequestHandler::makeNewHTTPConnection(int cb_evid_num, EVHTTPClientSession& sess)
{
	Poco::evnet::EVServer & server = getServer();
	long sr_num = 0;

	if (sess.getState() != EVHTTPClientSession::NOT_CONNECTED) {
		return -1;
	}

	sess.setAccfd(getAccSockfd());

	SRData * srdata = new SRData();
	srdata->addr = sess.getAddr();
	srdata->session_ptr = &sess;
	srdata->cb_evid_num = cb_evid_num;

	//DEBUGPOINT("Here Host empty = %d, bypass = %d\n", (int)proxyConfig().host.empty(), (int)bypassProxy(addr.host().toString()));
	if (proxyConfig().host.empty() || bypassProxy(sess.getAddr().host().toString())) {
		sr_num = server.submitRequestForConnection(HTTPRH_HTTPCONN_CONNECTION_ESTABLISHED, getAccSockfd(), sess.getAddr(), sess.getSS());
	}
	else {
		// TBD : Connect to proxy server first over here. TBD
		// Set callback to HTTPRH_HTTPCONN_PROXYSOCK_READY here
	}

	_srColl[sr_num] = srdata;

	return sr_num;
}

long EVHTTPRequestHandler::makeNewHTTPConnection(EventHandler& cb_handler, EVHTTPClientSession& sess)
{
	Poco::evnet::EVServer & server = getServer();
	long sr_num = 0;

	if (sess.getState() != EVHTTPClientSession::NOT_CONNECTED) {
		return -1;
	}

	sess.setAccfd(getAccSockfd());

	SRData * srdata = new SRData();
	srdata->addr = sess.getAddr();
	srdata->session_ptr = &sess;
	srdata->cb_evid_num = HTTPRH_CALL_CB_HANDLER;
	srdata->cb_handler = &cb_handler;

	//DEBUGPOINT("Here Host empty = %d, bypass = %d\n", (int)proxyConfig().host.empty(), (int)bypassProxy(addr.host().toString()));
	if (proxyConfig().host.empty() || bypassProxy(sess.getAddr().host().toString())) {
		sr_num = server.submitRequestForConnection(HTTPRH_HTTPCONN_CONNECTION_ESTABLISHED, getAccSockfd(), sess.getAddr(), sess.getSS());
	}
	else {
		// TBD : Connect to proxy server first over here. TBD
		// Set callback to HTTPRH_HTTPCONN_PROXYSOCK_READY here
	}

	_srColl[sr_num] = srdata;

	return sr_num;
}

long EVHTTPRequestHandler::waitForHTTPResponse(int cb_evid_num, EVHTTPClientSession& sess, EVHTTPResponse& res)
{
	Poco::evnet::EVServer & server = getServer();
	long sr_num = 0;

	if (sess.getState() != EVHTTPClientSession::CONNECTED) return -1;
	if (fcntl(sess.getSS().impl()->sockfd(), F_GETFD) < 0) return -1;

	SRData * srdata = new SRData();
	srdata->addr = sess.getAddr();
	srdata->session_ptr = &sess;
	srdata->cb_evid_num = cb_evid_num;
	srdata->response = &res;

	sr_num = server.submitRequestForRecvData(HTTPRH_HTTPRESP_MSG_FROM_HOST, getAccSockfd(), sess.getSS());

	_srColl[sr_num] = srdata;

	return sr_num;
}

long EVHTTPRequestHandler::waitForHTTPResponse(EventHandler& cb_handler, EVHTTPClientSession& sess, EVHTTPResponse& res)
{
	Poco::evnet::EVServer & server = getServer();
	long sr_num = 0;

	if (sess.getState() != EVHTTPClientSession::CONNECTED) return -1;
	if (fcntl(sess.getSS().impl()->sockfd(), F_GETFD) < 0) return -1;

	SRData * srdata = new SRData();
	srdata->addr = sess.getAddr();
	srdata->session_ptr = &sess;
	srdata->cb_evid_num = HTTPRH_CALL_CB_HANDLER;
	srdata->cb_handler = &cb_handler;
	srdata->response = &res;

	sr_num = server.submitRequestForRecvData(HTTPRH_HTTPRESP_MSG_FROM_HOST, getAccSockfd(), sess.getSS());

	_srColl[sr_num] = srdata;

	return sr_num;
}

*/

} } // namespace Poco::evnet
