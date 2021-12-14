//
// EVLHTTPRequestHandler.h
//
// Library: evnet
// Package: EVHTTPServer
// Module:  EVLHTTPRequestHandler
//
// Definition of the EVLHTTPRequestHandler class.
//
// Copyright (c) 2019-2020, Tekenlight Solutions Pvt Ltd
// and Contributors.
//
//


#ifndef Net_EVLHTTPRequestHandler_INCLUDED
#define Net_EVLHTTPRequestHandler_INCLUDED

/*
 * This is because lua compiles as ANSI C
 * and evpoco is in C++.
 * Name mangling for lua functions need to be
 * disabled.
 * */
extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <ev_queue.h>
#include <ev_rwlock.h>
}

#include "Poco/Util/AbstractConfiguration.h"
#include "Poco/evnet/EVHTTPRequestHandler.h"
#include "Poco/evnet/EVUpstreamEventNotification.h"
#include "Poco/Net/HTMLForm.h"
#include "Poco/Net/PartHandler.h"

#define PART_BUFFER_ALOC_SIZE 4096
#define EVL_EPH_BUFFER_SIZE 4096

#define MAX_MEMORY_ALLOC_LIMIT 0X40000000
#define S_CURRENT_ALLOC_SIZE "CURRENT_ALLOC_SIZE"
#define S_MAX_MEMORY_ALLOC_LIMIT "MAX_MEMORY_ALLOC_LIMIT"

namespace Poco {
namespace evnet {

class PartData {
public:
	PartData():_length(0)
	{
	}

	~PartData()
	{
	}

	void debug()
	{
		DEBUGPOINT("Length = %d\n", _length);
		DEBUGPOINT("Type = %s\n", _type.c_str());
		DEBUGPOINT("Name = %s\n", _name.c_str());
		Poco::Net::NameValueCollection::ConstIterator it = _params.begin();
		for (; it != _params.end(); ++it) {
			DEBUGPOINT("%s=%s\n", it->first.c_str(), it->second.c_str());
		}
	}

	int								_length;
	std::string						_type;
	std::string						_name;
	Poco::Net::NameValueCollection	_params;
	chunked_memory_stream			_cms;
};

class evl_async_task {
	public:
		typedef enum {
			NOACTION=0,
			MAKE_HTTP_CONNECTION,
			RECV_HTTP_RESPONSE
		} async_action;
		typedef enum {
			NOTSTARTED=-1,
			SUBMITTED,
			COMPLETE,
		} async_task_state;

		long							_task_srl_num;
		async_task_state				_task_tracking_state;
		async_action					_task_action;
		EVUpstreamEventNotification*	_usN;
		EVHTTPClientSession*			_session_ptr;
		EVHTTPResponse*					_response_ptr;
		evl_async_task(): _task_srl_num(0), _task_tracking_state(NOTSTARTED),
						_task_action(NOACTION), _usN(0), _session_ptr(0), _response_ptr(0) {}
		~evl_async_task() { if (_usN) delete _usN; if(_session_ptr) delete _session_ptr; if (_response_ptr) delete _response_ptr; }
};

class EVLHTTPPartHandler: public Poco::Net::PartHandler {
public:
	EVLHTTPPartHandler()
	{
	}

	~EVLHTTPPartHandler()
	{
		for ( std::map<std::string, PartData*>::iterator it = _parts.begin(); it != _parts.end(); ++it ) {
			delete it->second;
		}
		_parts.clear();
	}

	void handlePart(const Net::MessageHeader& header, std::istream& stream)
	{
		try {
			std::string fileName;
			PartData * p = new PartData();
			p->_type = header.get("Content-Type", "(unspecified)");
			if (header.has("Content-Disposition")) {
				std::string disp;
				Net::MessageHeader::splitParameters(header["Content-Disposition"], disp, p->_params);
				p->_name = p->_params.get("name", "(unnamed)");
				fileName = p->_params.get("filename", "(unnamed)");
			}

			char * buffer = NULL;
			while (!stream.eof()) {
				buffer = (char*)malloc(PART_BUFFER_ALOC_SIZE);

				stream.read(buffer, PART_BUFFER_ALOC_SIZE);
				std::streamsize size = stream.gcount();

				p->_cms.push(buffer, size);
				p->_length += size;

				buffer = NULL;
			}
			_parts[fileName] = p;

#ifdef MULTI_PART_TESTING
			{
				FILE * fp = fopen(fileName.c_str(), "w");
				if (!fp) { DEBUGPOINT("BAD\n"); abort(); }
				buffer = (char*)malloc(PART_BUFFER_ALOC_SIZE);
				size_t s;
				s = p->_cms.read(buffer, PART_BUFFER_ALOC_SIZE);
				while (s) {
					fwrite(buffer, s, 1, fp);
					s = p->_cms.read(buffer, PART_BUFFER_ALOC_SIZE);
				}
				free(buffer);
				fclose(fp);
			}
#endif

		} catch (std::exception& ex) {
			DEBUGPOINT("EXCEPTION HERE %s\n", ex.what());
			abort();
		}
	}

	std::map<std::string, PartData*>& getParts()
	{
		return _parts;
	}

private:
	std::map<std::string, PartData*>	_parts;
};

class evl_pool {
public:
	class queue_holder {
		public:
		queue_holder() { _queue = create_ev_queue(); }
		virtual ~queue_holder() { }
		virtual queue_holder * clone() = 0;
		ev_queue_type _queue;
	};
	evl_pool()
	{
		_lock = ev_rwlock_init();
	}

	~evl_pool()
	{
		ev_rwlock_destroy(_lock);
	}
	queue_holder * get_queue_holder(std::string name);
	queue_holder * add_queue_holder(std::string name, queue_holder *);

private:
	std::map<std::string, queue_holder*> _map;
	ev_rwlock_type _lock;
};

inline evl_pool::queue_holder * evl_pool::get_queue_holder(std::string name)
{
	evl_pool::queue_holder *qh = NULL;

	ev_rwlock_rdlock(_lock);
	{
		auto it = _map.find(name);
		if (_map.end() != it) qh = it->second;
		else qh =  NULL;
	}
	ev_rwlock_rdunlock(_lock);

	return qh;
}

inline evl_pool::queue_holder* evl_pool::add_queue_holder(std::string name, evl_pool::queue_holder *qh)
{
	evl_pool::queue_holder * i_qh = NULL;
	ev_rwlock_wrlock(_lock);
	auto it = _map.find(name);
	if (it == _map.end()) {
		i_qh = qh->clone();
		_map[name] = i_qh;
	} else {
		i_qh = it->second;
	}
	ev_rwlock_wrunlock(_lock);

	return i_qh;
}

class EVLHTTPRequestHandler;

class Net_API EVLHTTPRequestHandler : public EVHTTPRequestHandler
	/// The HTTP requesthandler implementation that enables
	/// handling of requests using LUA language
	/// created by EVHTTPServer.
	///
{
public:
	typedef std::map<long,evl_async_task *> async_tasks_t;

	typedef enum {
		 html_form
		,part_handler
		,string_body
	} mapped_item_type;

	EVLHTTPRequestHandler();
		/// Creates the EVLHTTPRequestHandler.

	virtual ~EVLHTTPRequestHandler();
		/// Destroys the EVLHTTPRequestHandler.

	virtual int handleRequest();
		/// Handles the given request.

	virtual std::string getMappingScript(const EVServerRequest* requestPtr) = 0;

	void addToComponents(mapped_item_type, void*);
	void* getFromComponents(mapped_item_type);
	int addHTTPConnection(EVHTTPClientSession* p);
	EVHTTPClientSession* getHTTPConnection(int i);
	std::string getDynamicMetaName();
	char* getEphemeralBuf();

	static const std::string SERVER_PREFIX_CFG_NAME;
	static const std::string ENABLE_CACHE;
	Poco::Util::AbstractConfiguration& appConfig();

	void track_async_task(long);
	void track_async_task(long, evl_async_task::async_action, EVHTTPClientSession*);
	void track_async_task(long, evl_async_task::async_action, EVHTTPResponse*);
	evl_async_task::async_task_state get_async_task_status(long);
	void set_async_task_tracking(long sr_num, evl_async_task::async_task_state st);
	EVUpstreamEventNotification* get_async_task_notification(long);
	evl_async_task* get_async_task(long sr_num);
	EVLHTTPRequestHandler::async_tasks_t& getAsyncTaskList();
	bool getAsyncTaskAwaited();
	void setAsyncTaskAwaited(bool);
	static evl_pool* getPool();
	static std::map<std::string, void*> * getMapOfMaps();
	static unsigned long getNextCachedStmtId();

private:
	EVLHTTPRequestHandler(const EVLHTTPRequestHandler&);
	EVLHTTPRequestHandler& operator = (const EVLHTTPRequestHandler&);

	void send_string_response(int line_no, const char * msg);
	int deduceReqHandler();
	int deduceFileToCall();
	int loadReqHandler();
	int loadReqMapper();
	int loadScriptToExec(std::string script_name);
	Poco::evnet::EVHTTPClientSession session;

	lua_State*									_L0;
	lua_State*									_L;
	std::string									_mapping_script;
	std::string									_request_handler;
	std::string									_url_part;
	std::map<mapped_item_type, void*>			_components;
	std::map<int,EVHTTPClientSession*>			_http_connections;
	std::list<std::string>						_url_parts;
	int											_http_connection_count;
	int											_variable_instance_count;;
	char										_ephemeral_buffer[EVL_EPH_BUFFER_SIZE];
	async_tasks_t								_async_tasks;
	bool										_async_tasks_status_awaited;
	static evl_pool								_pool;
	static std::map<std::string, void*>			_map_of_maps;
	//static std::atomic_ulong					_cached_stmt_id;
};

inline bool EVLHTTPRequestHandler::getAsyncTaskAwaited()
{
	return _async_tasks_status_awaited;
}

inline void EVLHTTPRequestHandler::setAsyncTaskAwaited(bool b)
{
	_async_tasks_status_awaited = b;
	return;
}

inline EVLHTTPRequestHandler::async_tasks_t& EVLHTTPRequestHandler::getAsyncTaskList()
{
	return _async_tasks;
}

inline char* EVLHTTPRequestHandler::getEphemeralBuf()
{
	return _ephemeral_buffer;
}

inline std::string EVLHTTPRequestHandler::getDynamicMetaName()
{
	char meta_name[100] ;
	sprintf(meta_name, "___%d___", ++_variable_instance_count);
	return std::string(meta_name);
}

inline int EVLHTTPRequestHandler::addHTTPConnection(EVHTTPClientSession* p)
{
	++_http_connection_count;
	_http_connections[_http_connection_count] = p;
	return _http_connection_count;
}

inline EVHTTPClientSession* EVLHTTPRequestHandler::getHTTPConnection(int i)
{
	auto it = _http_connections.find(i);
	if (_http_connections.end() != it) return it->second;
	else return NULL;
}

inline void EVLHTTPRequestHandler::addToComponents(mapped_item_type t, void* p)
{
	auto it = _components.find(t);
	if (_components.end() != it) {
		// This is to prevent inadvertent memory leakage
		switch (t) {
			case html_form:
				{
					Net::HTMLForm* form = (Net::HTMLForm*)it->second;
					delete form;
				}
				break;
			case part_handler:
				{
					EVLHTTPPartHandler* ph = (EVLHTTPPartHandler*)it->second;
					delete ph;
				}
				break;
			case string_body:
				{
					char* str = (char*)it->second;
					free(str);
				}
				break;
			default:
				break;
		}
	}
	_components[t] = p;
}

inline void* EVLHTTPRequestHandler::getFromComponents(mapped_item_type t)
{
	auto it = _components.find(t);
	if ( _components.end() != it) return it->second;
	else return NULL;
}

} } // namespace Poco::evnet


#endif // Net_EVLHTTPRequestHandler_INCLUDED
