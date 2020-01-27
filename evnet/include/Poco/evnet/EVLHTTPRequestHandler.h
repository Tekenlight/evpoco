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
}

#include "Poco/Util/AbstractConfiguration.h"
#include "Poco/evnet/EVHTTPRequestHandler.h"
#include "Poco/Net/HTMLForm.h"
#include "Poco/Net/PartHandler.h"

#define PART_BUFFER_ALOC_SIZE 4096
#define EVL_EPH_BUFFER_SIZE 4096

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

class EVLHTTPRequestHandler;

class Net_API EVLHTTPRequestHandler : public EVHTTPRequestHandler
	/// The HTTP requesthandler implementation that enables
	/// handling of requests using LUA language
	/// created by EVHTTPServer.
	///
{
public:
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

	virtual std::string getMappingScript(const Net::HTTPServerRequest& request) = 0;

	void addToComponents(mapped_item_type, void*);
	void* getFromComponents(mapped_item_type);
	int addHTTPConnection(EVHTTPClientSession* p);
	EVHTTPClientSession* getHTTPConnection(int i);
	std::string getDynamicMetaName();
	char* getEphemeralBuf();

	static const std::string SERVER_PREFIX_CFG_NAME;
	static const std::string ENABLE_CACHE;
	Poco::Util::AbstractConfiguration& appConfig();

private:
	EVLHTTPRequestHandler(const EVLHTTPRequestHandler&);
	EVLHTTPRequestHandler& operator = (const EVLHTTPRequestHandler&);

	void send_string_response(int line_no, const char * msg);
	int deduceReqHandler();
	int loadReqHandler();
	int loadReqMapper();
	Poco::evnet::EVHTTPClientSession session;

	lua_State*								_L0;
	lua_State*								_L;
	std::string								_mapping_script;
	std::string								_request_handler;
	std::string								_url_part;
	std::map<mapped_item_type, void*>		_components;
	std::map<int,EVHTTPClientSession*>		_http_connections;
	std::list<std::string>					_url_parts;
	int										_http_connection_count;
	int										_variable_instance_count;;
	char									_ephemeral_buffer[EVL_EPH_BUFFER_SIZE];
};

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
	return _http_connections[i];
}

inline void EVLHTTPRequestHandler::addToComponents(mapped_item_type t, void* p)
{
	if (_components[t]) {
		// This is to prevent inadvertent memory leakage
		switch (t) {
			case html_form:
				{
					Net::HTMLForm* form = (Net::HTMLForm*)_components[t];
					delete form;
				}
				break;
			case part_handler:
				{
					EVLHTTPPartHandler* ph = (EVLHTTPPartHandler*)_components[t];
					delete ph;
				}
				break;
			case string_body:
				{
					char* str = (char*)_components[t];
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
	return _components[t];
}


} } // namespace Poco::evnet


#endif // Net_EVLHTTPRequestHandler_INCLUDED
