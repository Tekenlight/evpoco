//
// EVHTTPRequestHandler.h
//
// Library: evnet
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

#include <ostream>
#include <map>

#include <functional>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "Poco/Net/Net.h"
#include "Poco/Net/HTTPRequestHandler.h"
#include "Poco/Net/HTTPClientSession.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/evnet/EVHTTPRequest.h"
#include "Poco/evnet/EVHTTPClientSession.h"
#include "Poco/evnet/EVHTTPServerRequestImpl.h"
#include "Poco/evnet/EVHTTPServerResponseImpl.h"
#include "Poco/evnet/EVCLServerRequestImpl.h"
#include "Poco/evnet/EVCLServerResponseImpl.h"
#include "Poco/evnet/evnet.h"
#include "Poco/evnet/EVEventNotification.h"
#include "Poco/evnet/EVAcceptedStreamSocket.h"
#include "Poco/evnet/EVServer.h"


namespace Poco {
namespace evnet {

class file_handle {
public:
	file_handle() : _fd(-1) {}
	~file_handle() {}
	int get_fd()
	{
		return _fd;
	}
	void set_fd(int f)
	{
		_fd = f;
	}

private:
	int _fd;
};

typedef file_handle* file_handle_p;


class EVHTTPRequestHandler;

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
	typedef enum {
		NONE = 0
		,READ = 1
		,WRITE = 2
		,READWRITE = 3
	} poll_for;

	enum EVHTTP_RH_MODE {
		SERVER_MODE = 0, COMMAND_LINE_MODE = 1, WEBSOCKET_MODE = 2
	};

	typedef std::function<int ()> TCallback;
	typedef std::function<void ()> VTCallback;

	class EventHandler {
		public:
		EventHandler() { }
		virtual int operator ()() =0;
	};

	struct SRData {
		SRData(): cb_evid_num(0), session_ptr(0), response(0), cb_handler(0), cb(0), addr_info_ptr_ptr(0),
				  domain_name(0), serv_name(0), port_num(0), ref_sr_num(-1), ss_ptr(0) {}
		~SRData() { if (ss_ptr) delete ss_ptr;}
		Net::SocketAddress		addr;
		EVHTTPClientSession*	session_ptr;
		int						cb_evid_num;
		EVHTTPResponse*			response;
		EventHandler*			cb_handler;
		TCallback				cb;
		const char*				domain_name;
		const char*				serv_name;
		unsigned short			port_num;
		struct addrinfo**       addr_info_ptr_ptr;
		long					ref_sr_num;
		Net::StreamSocket*		ss_ptr;
	} ;

	typedef std::map<long,SRData *> SRColMapType;
	typedef std::map<int,file_handle*> FilesMapType;
	static const int INITIAL = 0;

	/* Return values of handleRequest method. */
	static const int INVALID_STATE = -1;
	static const int PROCESSING_ERROR = -1000;
	static const int PROCESSING = 0;
	static const int PROCESSING_COMPLETE = 1000;

	static const int HTTPRH_INVALID_CB_NUM = -1;

	static const int HTTPRH_DNSR_HOST_RESOLUTION_DONE = -100;

	static const int HTTPRH_HTTPCONN_HOSTRESOLVED = -200;
	static const int HTTPRH_HTTPCONN_PROXYSOCK_READY = -210;
	static const int HTTPRH_HTTPCONN_PROXY_RESPONSE = -220;
	static const int HTTPRH_HTTPCONN_CONNECTION_ESTABLISHED = -230;

	static const int HTTPRH_HTTPRESP_MSG_FROM_HOST = -300;

	static const int HTTPRH_TCPCONN_HOSTRESOLVED = -400;
	static const int HTTPRH_TCPCONN_PROXYSOCK_READY = -410;
	static const int HTTPRH_TCPCONN_PROXY_RESPONSE = -420;
	static const int HTTPRH_TCPCONN_CONNECTION_ESTABLISHED = -430;


	static const int HTTPRH_CALL_CB_HANDLER = -10000;

	EVHTTPRequestHandler();
		/// Creates the EVHTTPRequestHandler.

	virtual ~EVHTTPRequestHandler();
		/// Destroys the EVHTTPRequestHandler.

	virtual int handleRequest() = 0;
		/// Must be overridden by subclasses.
		///
		/// Handles the given request.

	int handleRequestSurrogate();
	int handleRequestSurrogateInitial();

	int getState();
	void setState(int);
	EVEventNotification & getUNotification();
	void setUNotification(EVEventNotification *);
	int getEvent();
	EVServer& getServer();
	EVServer* getServerPtr();
	void setServer(EVServer * server);
	poco_socket_t getAccSockfd();
	void setAccSockfd(poco_socket_t fd);
	EVHTTPServerRequestImpl& getHTTPRequest();
	EVHTTPServerRequestImpl* getHTTPRequestPtr();
	EVCLServerRequestImpl* getCLRequestPtr();
	void setHTTPRequest(EVHTTPServerRequestImpl* req);
	void setCLRequest(EVCLServerRequestImpl* cl_req);
	EVHTTPServerResponseImpl& getHTTPResponse();
	EVHTTPServerResponseImpl* getHTTPResponsePtr();
	EVCLServerResponseImpl* getCLResponsePtr();
	void setHTTPResponse(EVHTTPServerResponseImpl* res);
	void setCLResponse(EVCLServerResponseImpl* cl_res);
	void setAcceptedSocket(EVAcceptedStreamSocket * tn);
	EVAcceptedStreamSocket* getAcceptedSocket();

	/*
	long waitForHTTPResponse(int cb_evid_num, EVHTTPClientSession& sess, EVHTTPResponse &req);
	long waitForHTTPResponse(EventHandler& cb_handler, EVHTTPClientSession& sess, EVHTTPResponse& res);

	long makeNewSocketConnection(int cb_evid_num, Net::SocketAddress& addr, Net::StreamSocket& css);
	long makeNewSocketConnection(EventHandler& cb_handler, Net::SocketAddress& addr, Net::StreamSocket& css);

	long makeNewHTTPConnection(int cb_evid_num, EVHTTPClientSession& sess);
	long makeNewHTTPConnection(EventHandler& cb_handler, EVHTTPClientSession& sess);
	 *
	 */

	long pollFileOpenStatus(TCallback cb, int fd);
	long pollFileReadStatus(TCallback cb, int fd);
	long executeGenericTask(TCallback cb, generic_task_handler_t tf, void * input_data);
	static void executeGenericTaskNR(Poco::evnet::EVServer & server, generic_task_handler_nr_t tf, void * input_data);
	void executeGenericTaskNR(generic_task_handler_nr_t tf, void * input_data);

	long resolveHost(TCallback cb, const char* domain_name, const char* serv_name, struct addrinfo ** addr_info_ptr_ptr);

	long makeNewHTTPConnection(TCallback cb, const char * domain_name, const char * serv_name, EVHTTPClientSession& sess);
	long makeNewHTTPConnection(TCallback cb, const char * domain_name, const unsigned short port_num, EVHTTPClientSession& sess);
	long makeNewHTTPConnection(TCallback cb, EVHTTPClientSession& sess);

	long makeNewSocketConnection(TCallback cb, Net::SocketAddress& addr, Net::StreamSocket& css);
	long makeNewSocketConnection(TCallback cb, const char * domain_name, const unsigned short port_num);
	long pollSocketForReadOrWrite(TCallback cb, int fd, int poll_for, int managed = 1);
	long redistransceive(TCallback cb, redisAsyncContext *ac, const char * message);
	void redisDisconnect(TCallback cb, redisAsyncContext *ac);

	long waitForHTTPResponse(TCallback cb, EVHTTPClientSession& sess, EVHTTPResponse& res);

	long sendHTTPHeader(EVHTTPClientSession &sess, EVHTTPRequest &req);
	long sendHTTPRequestData(EVHTTPClientSession &ses, EVHTTPRequest & req);
	long sendRawDataOnAccSocket(Net::StreamSocket& accss, void* data, size_t len);
	long trackAsWebSocket(Net::StreamSocket& connss, const char * msg_handler);
	long evTimer(int time_in_ms);
	long shutdownWebSocket(Net::StreamSocket &ss, int type = 3);
	long stopTakingRequests();
	long webSocketActive(Net::StreamSocket &ss);

	long closeHTTPSession(EVHTTPClientSession& sess);

	file_handle_p ev_file_open(const char * path, int oflag, ...);
	ssize_t ev_file_read(file_handle_p fh, void *buf, size_t nbyte);
	ssize_t ev_file_write(file_handle_p fh, void *buf, size_t nbyte);
	int ev_file_close(file_handle_p fh);
	file_handle_p ev_get_file_handle(int fd);
	void setEVRHMode(int mode);
	int getEVRHMode();

private:
	EVHTTPRequestHandler(const EVHTTPRequestHandler&);
	EVHTTPRequestHandler& operator = (const EVHTTPRequestHandler&);
	bool bypassProxy(std::string host);
	const Net::HTTPClientSession::ProxyConfig& proxyConfig();

	int								_state;
	EVEventNotification*	_usN;
	EVServer*						_server;
	poco_socket_t					_acc_fd;
	EVAcceptedStreamSocket*			_tn;
	EVHTTPServerRequestImpl*		_req = NULL;
	EVHTTPServerResponseImpl*		_rsp = NULL;
	EVCLServerRequestImpl*			_cl_req = NULL;
	EVCLServerResponseImpl*			_cl_rsp = NULL;
	SRColMapType					_srColl;
	FilesMapType					_opened_files;
	int								_ev_rh_mode;
};

inline int EVHTTPRequestHandler::getEVRHMode()
{
	return _ev_rh_mode;
}

inline void EVHTTPRequestHandler::setEVRHMode(int mode)
{
	_ev_rh_mode = mode;
}

inline void EVHTTPRequestHandler::setAcceptedSocket(EVAcceptedStreamSocket * tn)
{
	_tn = tn;
}

inline EVAcceptedStreamSocket* EVHTTPRequestHandler::getAcceptedSocket()
{
	return _tn;
}

inline file_handle_p EVHTTPRequestHandler::ev_get_file_handle(int fd)
{
	FilesMapType::iterator it = _opened_files.find(fd);
	if (it == _opened_files.end()) return NULL;
	return it->second;
}

inline EVEventNotification & EVHTTPRequestHandler::getUNotification()
{
	return *_usN;
}

inline void EVHTTPRequestHandler::setUNotification(EVEventNotification * usN)
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

inline EVServer* EVHTTPRequestHandler::getServerPtr()
{
	return _server;
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

inline EVHTTPServerRequestImpl* EVHTTPRequestHandler::getHTTPRequestPtr()
{
	return _req;
}

inline EVCLServerRequestImpl* EVHTTPRequestHandler::getCLRequestPtr()
{
	return _cl_req;
}

inline EVHTTPServerRequestImpl& EVHTTPRequestHandler::getHTTPRequest()
{
	return *_req;
}

inline void EVHTTPRequestHandler::setCLRequest(EVCLServerRequestImpl* cl_req)
{
	_cl_req = cl_req;
}

inline void EVHTTPRequestHandler::setHTTPRequest(EVHTTPServerRequestImpl* req)
{
	_req = req;
}

inline EVCLServerResponseImpl* EVHTTPRequestHandler::getCLResponsePtr()
{
	return _cl_rsp;
}

inline EVHTTPServerResponseImpl* EVHTTPRequestHandler::getHTTPResponsePtr()
{
	return _rsp;
}

inline EVHTTPServerResponseImpl& EVHTTPRequestHandler::getHTTPResponse()
{
	return *_rsp;
}

inline void EVHTTPRequestHandler::setCLResponse(EVCLServerResponseImpl* cl_rsp)
{
	_cl_rsp = cl_rsp;
}

inline void EVHTTPRequestHandler::setHTTPResponse(EVHTTPServerResponseImpl* rsp)
{
	_rsp = rsp;
}

inline const Net::HTTPClientSession::ProxyConfig& EVHTTPRequestHandler::proxyConfig()
{
	return Net::HTTPClientSession::getGlobalProxyConfig();
}


} } // namespace Poco::evnet


#endif // Net_EVHTTPRequestHandler_INCLUDED
