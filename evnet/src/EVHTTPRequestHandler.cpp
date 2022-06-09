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
#include <stdarg.h>

#include <ef_io.h>

#include "Poco/Net/HostEntry.h"
#include "Poco/Net/HostEntry.h"
#include "Poco/evnet/EVHTTPRequestHandler.h"
#include "Poco/RegularExpression.h"


namespace Poco {
namespace evnet {


EVHTTPRequestHandler::EVHTTPRequestHandler():
	_state(INITIAL),
	_ev_rh_mode(0)
{
}


EVHTTPRequestHandler::~EVHTTPRequestHandler()
{
    for (SRColMapType::iterator it = _srColl.begin(); it != _srColl.end(); ++it ) {
        delete it->second;
    }
    _srColl.clear();

	/* Close all the unclosed files. */
	for (FilesMapType::iterator it = _opened_files.begin(); it != _opened_files.end(); ++it)  {
		ef_close(it->first);
		delete it->second;
	}
	_opened_files.clear();
}

int EVHTTPRequestHandler::getState()
{
	return _state;
}

void EVHTTPRequestHandler::setState(int state)
{
	_state = state;
}

// This is a fire and forget call
void EVHTTPRequestHandler::redisDisconnect(TCallback cb, redisAsyncContext *ac)
{
	//SRData * srdata = new SRData();
	
	Poco::evnet::EVServer & server = getServer();

	//srdata->cb_evid_num = HTTPRH_CALL_CB_HANDLER;
	//srdata->cb = cb;

	server.redisDisconnect(HTTPRH_CALL_CB_HANDLER, getAcceptedSocket(), ac);

	//srdata->ref_sr_num = sr_num;
	//_srColl[sr_num] = srdata;

	return ;
}

long EVHTTPRequestHandler::redistransceive(TCallback cb, redisAsyncContext *ac, const char * message)
{
	long sr_num = 0;
	SRData * srdata = new SRData();
	
	Poco::evnet::EVServer & server = getServer();

	srdata->cb_evid_num = HTTPRH_CALL_CB_HANDLER;
	srdata->cb = cb;

	sr_num = server.redistransceive(HTTPRH_CALL_CB_HANDLER, getAcceptedSocket(), ac,  message);

	srdata->ref_sr_num = sr_num;
	_srColl[sr_num] = srdata;

	return sr_num;
}

long EVHTTPRequestHandler::pollSocketForReadOrWrite(TCallback cb, int fd, int poll_for, int managed)
{
	Net::StreamSocket css;
	Poco::evnet::EVServer & server = getServer();
	long sr_num = 0;
	SRData * srdata = new SRData();

	srdata->cb_evid_num = HTTPRH_CALL_CB_HANDLER;
	srdata->cb = cb;

	css.setFd(fd);
	sr_num = server.submitRequestForPoll(HTTPRH_CALL_CB_HANDLER, getAcceptedSocket(), css, poll_for, managed);

	srdata->ref_sr_num = sr_num;
	_srColl[sr_num] = srdata;

	//DEBUGPOINT("Service Request Number = %ld\n", sr_num);
	return sr_num;
}

long EVHTTPRequestHandler::makeNewSocketConnection(TCallback cb, Net::SocketAddress& addr, Net::StreamSocket& css)
{
	Poco::evnet::EVServer & server = getServer();
	long sr_num = 0;
	SRData * srdata = new SRData();

	srdata->addr = addr;
	srdata->cb_evid_num = HTTPRH_CALL_CB_HANDLER;
	srdata->cb = cb;
	sr_num = server.submitRequestForConnection(HTTPRH_CALL_CB_HANDLER, getAcceptedSocket(), addr, css);

	srdata->ref_sr_num = sr_num;
	_srColl[sr_num] = srdata;

	DEBUGPOINT("Service Request Number = %ld\n", sr_num);
	return sr_num;
}

long EVHTTPRequestHandler::makeNewSocketConnection(TCallback cb,
					const char * domain_name, const unsigned short port_num)
{
	Poco::evnet::EVServer & server = getServer();
	long sr_num = 0;

	SRData * srdata = new SRData();
	srdata->session_ptr = NULL;
	srdata->cb_evid_num = HTTPRH_TCPCONN_HOSTRESOLVED;
	srdata->cb = cb;
	srdata->domain_name = domain_name;
	srdata->serv_name = NULL;
	srdata->port_num = port_num;

	sr_num =  getServer().submitRequestForHostResolution(HTTPRH_TCPCONN_HOSTRESOLVED, getAcceptedSocket(), domain_name, NULL);

	srdata->ref_sr_num = sr_num;
	_srColl[sr_num] = srdata;

	return sr_num;
}

long EVHTTPRequestHandler::closeHTTPSession(EVHTTPClientSession& sess)
{
	sess.setState(EVHTTPClientSession::CLOSED);
	getServer().submitRequestForClose(getAcceptedSocket(), sess.getSS());
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
		sr_num = server.submitRequestForConnection(HTTPRH_HTTPCONN_CONNECTION_ESTABLISHED, getAcceptedSocket(), sess.getAddr(), sess.getSS());
	}
	else {
		// TBD : Connect to proxy server first over here. TBD
		// Set callback to HTTPRH_HTTPCONN_PROXYSOCK_READY here
	}

	srdata->ref_sr_num = sr_num;
	_srColl[sr_num] = srdata;

	return sr_num;
}





/*
 * HTTP2 enhancement
 * Have to write a new set of methods and classes
 * to handle the client side of HTTP2 request and 
 * response handling
 */




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

	sr_num =  getServer().submitRequestForHostResolution(HTTPRH_HTTPCONN_HOSTRESOLVED, getAcceptedSocket(), domain_name, NULL);

	srdata->ref_sr_num = sr_num;
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

	sr_num =  getServer().submitRequestForHostResolution(HTTPRH_HTTPCONN_HOSTRESOLVED, getAcceptedSocket(), domain_name, serv_name);

	srdata->ref_sr_num = sr_num;
	_srColl[sr_num] = srdata;

	return sr_num;
}

long EVHTTPRequestHandler::sendHTTPHeader(EVHTTPClientSession &sess, EVHTTPRequest &req)
{
	if (sess.getState() != EVHTTPClientSession::CONNECTED) return -1;
	if (fcntl(sess.getSS().impl()->sockfd(), F_GETFD) < 0) return -1;
	req.prepareHeaderForSend();
	sess.getSendStream()->transfer(req.getMessageHeader());
	getServer().submitRequestForSendData(getAcceptedSocket(), sess.getSS());

	return 0;
}

/* This method assumes that input HTTPRequest is completely formed. */
long EVHTTPRequestHandler::sendHTTPRequestData(EVHTTPClientSession &sess, EVHTTPRequest &req)
{
	if (sess.getState() != EVHTTPClientSession::CONNECTED) return -1;
	if (fcntl(sess.getSS().impl()->sockfd(), F_GETFD) < 0) return -1;
	sess.getSendStream()->transfer(req.getMessageBody());
	getServer().submitRequestForSendData(getAcceptedSocket(), sess.getSS());

	return 0;
}

long EVHTTPRequestHandler::trackAsWebSocket(Net::StreamSocket& connss, const char * msg_handler)
{
	getServer().trackAsWebSocket(HTTPRH_CALL_CB_HANDLER, getAcceptedSocket(), connss, msg_handler);
	return 0;
}

long EVHTTPRequestHandler::sendRawDataOnAccSocket(Net::StreamSocket& accss, void* data, size_t len)
{
	getServer().sendRawDataOnAccSocket(HTTPRH_CALL_CB_HANDLER, getAcceptedSocket(), accss, data, len);
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

	sr_num = server.submitRequestForRecvData(HTTPRH_HTTPRESP_MSG_FROM_HOST, getAcceptedSocket(), sess.getSS());

	srdata->ref_sr_num = sr_num;
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

	sr_num =  getServer().submitRequestForHostResolution(HTTPRH_DNSR_HOST_RESOLUTION_DONE, getAcceptedSocket(), domain_name, serv_name);
	srdata->ref_sr_num = sr_num;
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

long EVHTTPRequestHandler::pollFileOpenStatus(TCallback cb, int fd)
{
	long sr_num = 0;

	SRData * srdata = new SRData();
	srdata->cb_evid_num = HTTPRH_CALL_CB_HANDLER;
	srdata->cb = cb;

	sr_num =  getServer().notifyOnFileOpen(HTTPRH_CALL_CB_HANDLER, getAcceptedSocket(), fd);
	srdata->ref_sr_num = sr_num;
	_srColl[sr_num] = srdata;

	return sr_num;
}

long EVHTTPRequestHandler::pollFileReadStatus(TCallback cb, int fd)
{
	Poco::evnet::EVServer & server = getServer();
	long sr_num = 0;

	SRData * srdata = new SRData();
	srdata->cb_evid_num = HTTPRH_CALL_CB_HANDLER;
	srdata->cb = cb;

	sr_num =  getServer().notifyOnFileRead(HTTPRH_CALL_CB_HANDLER, getAcceptedSocket(), fd);
	srdata->ref_sr_num = sr_num;
	_srColl[sr_num] = srdata;

	return sr_num;
}

long EVHTTPRequestHandler::executeGenericTask(TCallback cb, generic_task_handler_t tf, void * input_data)
{
	Poco::evnet::EVServer & server = getServer();
	long sr_num = 0;

	SRData * srdata = new SRData();
	srdata->cb_evid_num = HTTPRH_CALL_CB_HANDLER;
	srdata->cb = cb;

	//DEBUGPOINT("Here\n");
	sr_num =  getServer().submitRequestForTaskExecution(HTTPRH_CALL_CB_HANDLER, getAcceptedSocket(), tf, input_data);
	srdata->ref_sr_num = sr_num;
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
	//if (!_srColl[sr_num]) return PROCESSING; Linux porting change
	auto it = _srColl.find(sr_num);
	if (_srColl.end() == it) return PROCESSING;
	//DEBUGPOINT("Here event = %d, \n", getEvent());

	switch (getEvent()) {
		case HTTPRH_HTTPCONN_CONNECTION_ESTABLISHED:
			_usN->setCBEVIDNum((it->second)->cb_evid_num);
			if ((_usN->getRet() < 0) || _usN->getErrNo()) {
				it->second->session_ptr->setState(EVHTTPClientSession::IN_ERROR);
			}
			else {
				/* No proxy or it has to be bypassed. */
				it->second->session_ptr->setState(EVHTTPClientSession::CONNECTED);
				it->second->session_ptr->setRecvStream(_usN->getRecvStream());
				it->second->session_ptr->setSendStream(_usN->getSendStream());
			}
			break;
		case HTTPRH_TCPCONN_CONNECTION_ESTABLISHED:
			_usN->setCBEVIDNum((it->second)->cb_evid_num);
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
					it->second->session_ptr->setState(EVHTTPClientSession::IN_ERROR);
					_usN->setCBEVIDNum((it->second)->cb_evid_num);
				}
				else {
					it->second->session_ptr->setRecvStream(_usN->getRecvStream());
					it->second->session_ptr->setSendStream(_usN->getSendStream());
					parse_ret = it->second->session_ptr->continueRead(*(it->second->response));
					if (parse_ret < 0) {
						_usN->setRet(-1);
						closeHTTPSession(*(it->second->session_ptr));
						_usN->setCBEVIDNum((it->second)->cb_evid_num);
					}
					else if (parse_ret < MESSAGE_COMPLETE) {
						SRData * old = it->second;
						SRData * srdata = new SRData(*old);
						_srColl.erase(sr_num);
						delete old;
						Poco::evnet::EVServer & server = getServer();
						sr_num = server.submitRequestForRecvData(HTTPRH_HTTPRESP_MSG_FROM_HOST,
											getAcceptedSocket(), srdata->session_ptr->getSS());
						_srColl[sr_num] = srdata;
						continue_event_loop = true;
					}
					else {
						if (!(it->second->response->getVersion().compare("HTTP/1.0"))) {
							//DEBUGPOINT("Got a response of version 1.0\n");
							closeHTTPSession(*(it->second->session_ptr));
						}
						_usN->setCBEVIDNum((it->second)->cb_evid_num);
					}
				}
			}
			break;
		case HTTPRH_HTTPCONN_HOSTRESOLVED:
			{
				if (_usN->getRet() != 0) {
					it->second->session_ptr->setState(EVHTTPClientSession::IN_ERROR);
					_usN->setCBEVIDNum((it->second)->cb_evid_num);
				}
				else {
					SRData * old = it->second;
					SRData * srdata = new SRData(*old);
					_srColl.erase(sr_num);
					delete old;
					Net::HostEntry he(_usN->getAddrInfo());
#ifdef NEVER_DEBUG
					{
						int i = 0;
						struct addrinfo *p;
						char host[256];

						for (p = _usN->getAddrInfo(); p; p = p->ai_next) {
							i++;
							getnameinfo(p->ai_addr, p->ai_addrlen, host, sizeof (host), NULL, 0, NI_NUMERICHOST);
							DEBUGPOINT("%d. %s   ", i, host);

							if (p->ai_addr->sa_family == AF_INET) { DEBUGPOINT("IPV4 ADDRESS\n"); }
							else { DEBUGPOINT("IPV6 ADDRESS\n");}
						}
					}
#endif
					Net::SocketAddress a(srdata->domain_name, he, srdata->port_num);
					srdata->addr = a;
					srdata->session_ptr->setAddr(a);
					Poco::evnet::EVServer & server = getServer();
					if (proxyConfig().host.empty() || bypassProxy(srdata->session_ptr->getAddr().host().toString())) {

						sr_num = server.submitRequestForConnection(HTTPRH_HTTPCONN_CONNECTION_ESTABLISHED,
									getAcceptedSocket(), srdata->session_ptr->getAddr(), srdata->session_ptr->getSS());
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
		case HTTPRH_TCPCONN_HOSTRESOLVED:
			{
				if ((_usN->getRet() < 0) || _usN->getErrNo()) {
					_usN->setCBEVIDNum((it->second)->cb_evid_num);
				}
				else {
					SRData * old = it->second;
					SRData * srdata = new SRData(*old);
					_srColl.erase(sr_num);
					delete old;
					Net::HostEntry he(_usN->getAddrInfo());
#ifdef NEVER_DEBUG
					{
						int i = 0;
						struct addrinfo *p;
						char host[256];

						for (p = _usN->getAddrInfo(); p; p = p->ai_next) {
							i++;
							getnameinfo(p->ai_addr, p->ai_addrlen, host, sizeof (host), NULL, 0, NI_NUMERICHOST);
							DEBUGPOINT("%d. %s   \n", i, host);

							if (p->ai_addr->sa_family == AF_INET) { DEBUGPOINT("IPV4 ADDRESS\n"); }
							else { DEBUGPOINT("IPV6 ADDRESS\n");}
						}
					}
#endif
					Net::SocketAddress a(srdata->domain_name, he, srdata->port_num);
					srdata->addr = a;
					Poco::evnet::EVServer & server = getServer();
					if (proxyConfig().host.empty()) {

						srdata->ss_ptr = new Net::StreamSocket();
						sr_num = server.submitRequestForConnection(HTTPRH_TCPCONN_CONNECTION_ESTABLISHED,
									getAcceptedSocket(), srdata->addr, *(srdata->ss_ptr));
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
			*(it->second->addr_info_ptr_ptr) = _usN->getAddrInfo();
			break;
		case HTTPRH_CALL_CB_HANDLER:
		default:
			break;
	}

	if (continue_event_loop) {
		ret = PROCESSING;
	}
	else {
		SRData * old = it->second;
		_usN->setRefSRNum(old->ref_sr_num);
		try {
			if ((it->second)->cb_handler) {
				ret = (*((it->second)->cb_handler))();
			}
			else if (0 != (it->second)->cb) {
				ret = (it->second)->cb();
			}
			else {
				ret = handleRequest();
			}
		}
		catch (...) {
			ret = PROCESSING_ERROR;
		}
		_srColl.erase(sr_num);
		delete old;
	}

	//DEBUGPOINT("Here ret = %d\n", ret);
	return (ret<0)?PROCESSING_ERROR:ret;
}

file_handle* EVHTTPRequestHandler::ev_file_open(const char * path, int oflag, ...)
{
	int fd = -1;
	if (O_CREAT&oflag) {
		int mode;
		va_list ap;
		va_start(ap,oflag);
		mode= (mode_t)va_arg(ap,int);
		va_end(ap);
		fd = ef_open(path, oflag, mode);
	}
	else {
		fd = ef_open(path, oflag);
	}
	
	/* Track the files */
	file_handle *fh = NULL;
	if (fd != -1) {
		fh = new file_handle();
		fh->set_fd(fd);
		_opened_files[fd] = fh;
	}

	return fh;
}

ssize_t EVHTTPRequestHandler::ev_file_read(file_handle* fh, void * buf, size_t nbyte)
{
	return ef_read(fh->get_fd(), buf, nbyte);
}

ssize_t EVHTTPRequestHandler::ev_file_write(file_handle* fh, void *buf, size_t nbyte)
{
	return ef_write(fh->get_fd(), buf, nbyte);
}

int EVHTTPRequestHandler::ev_file_close(file_handle* fh)
{
	ef_close(fh->get_fd());
	_opened_files.erase(fh->get_fd());
	delete fh;
	return 0;
}


} } // namespace Poco::evnet
