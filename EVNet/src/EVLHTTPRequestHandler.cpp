//
// EVLHTTPRequestHandler.cpp
//
// Library: EVNet
// Package: EVHTTPServer
// Module:  EVLHTTPRequestHandler
//
// Copyright (c) 2019-2020, Tekenlight Solutions Pvt Ltd
//

#include <chunked_memory_stream.h>

#include "Poco/EVNet/EVLHTTPRequestHandler.h"
#include "Poco/Net/HTTPServerResponse.h"
#include "Poco/Net/HTTPServerRequest.h"
#include "Poco/Net/HTMLForm.h"
#include "Poco/Net/PartHandler.h"
#include "Poco/Net/MessageHeader.h"
#include "Poco/CountingStream.h"
#include "Poco/NullStream.h"
#include "Poco/StreamCopier.h"
#include "Poco/DateTimeParser.h"
#include "Poco/DateTime.h"
#include "Poco/URI.h"


namespace Poco {
namespace EVNet {

#define PART_BUFFER_ALOC_SIZE 4096

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

class EVLHTTPPartHandler: public Poco::Net::PartHandler
{
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

const static char *_resp_output_stream = "respostr";
const static char *_html_form_type_name = "htmlform";
const static char *_http_req_type_name = "httpreq";
const static char *_http_resp_type_name = "httpresp";
const static char *_platform_name = "context";

static int obj__gc(lua_State *L)
{
	return 0;
}

namespace evpoco {
	static EVLHTTPRequestHandler* get_req_handler_instance(lua_State* L)
	{
		lua_getglobal(L, "EVLHTTPRequestHandler*");
		EVLHTTPRequestHandler * req_h = (EVLHTTPRequestHandler*)lua_touserdata(L, -1);
		lua_pop(L, 1);
		return req_h;
	}

	static int evpoco_yield(lua_State* L)
	{
		//DEBUGPOINT("Here\n");
		return lua_yield(L, 0);
	}

	static int get_http_request(lua_State* L)
	{
		EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
		Net::HTTPServerRequest& request = reqHandler->getRequest();

		void * ptr = lua_newuserdata(L, sizeof(Net::HTTPServerRequest*));
		*(Net::HTTPServerRequest**)ptr = &request;
		luaL_setmetatable(L, _http_req_type_name);

		return 1;
	}

	static int get_http_response(lua_State* L)
	{
		EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
		Net::HTTPServerResponse& response = reqHandler->getResponse();

		void * ptr = lua_newuserdata(L, sizeof(Net::HTTPServerResponse*));
		*(Net::HTTPServerResponse**)ptr = &response;
		luaL_setmetatable(L, _http_resp_type_name);

		return 1;
	}

	namespace httpmessage {
		static int set_version(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
				luaL_error(L, "set_version: inalid first argumet %s", lua_typename(L, lua_type(L, -2)));
				return 0;
			}
			else if (lua_isnil(L, -1) || !lua_isstring(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "set_version: inalid second argumet %s", lua_typename(L, lua_type(L, -1)));
				return 0;
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -2));
				const char* value = lua_tostring(L, -1);
				if (!(*value)) {
					DEBUGPOINT("Here Invalid  value =%s\n", value);
					luaL_error(L, "set_version: Invalid value=%s", value);
					return 0;
				}
				message.setVersion(value);
			}
			return 0;
		}

		static int get_version(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
				luaL_error(L, "get_version: inalid argumet %s", lua_typename(L, lua_type(L, -1)));
				lua_pushnil(L);
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -1));
				std::string hdr_fld_value = message.getVersion();
				lua_pushstring(L, hdr_fld_value.c_str());
			}
			return 1;
		}

		static int set_chunked_trfencoding(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
				luaL_error(L, "set_chunked_trfencoding: inalid first argumet %s", lua_typename(L, lua_type(L, -2)));
				return 0;
			}
			else if (lua_isnil(L, -1) || !lua_isboolean(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "set_chunked_trfencoding: inalid second argumet %s", lua_typename(L, lua_type(L, -1)));
				return 0;
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -2));
				const int value = lua_toboolean(L, -1);
				message.setChunkedTransferEncoding(value);
			}
			return 0;
		}

		static int get_chunked_trfencoding(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "get_chunked_trfencoding: inalid argumet %s", lua_typename(L, lua_type(L, -1)));
				lua_pushnil(L);
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -1));
				int hdr_fld_value = message.getChunkedTransferEncoding();
				lua_pushboolean(L, hdr_fld_value);
			}
			return 1;
		}

		static int set_content_length(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
				luaL_error(L, "set_content_length: inalid first argumet %s", lua_typename(L, lua_type(L, -2)));
				return 0;
			}
			else if (lua_isnil(L, -1) || !lua_isinteger(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "set_content_length: inalid second argumet %s", lua_typename(L, lua_type(L, -1)));
				return 0;
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -2));
				int value = 0; lua_numbertointeger(lua_tonumber(L, -1), &value);
				message.setContentLength(value);
			}
			return 0;
		}

		static int get_content_length(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "get_content_length: inalid argumet %s", lua_typename(L, lua_type(L, -1)));
				lua_pushnil(L);
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -1));
				int hdr_fld_value = message.getContentLength();
				lua_pushinteger(L, hdr_fld_value);
			}
			return 1;
		}

		static int set_trf_encoding(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
				luaL_error(L, "set_trf_encoding: inalid first argumet %s", lua_typename(L, lua_type(L, -3)));
				return 0;
			}
			else if (lua_isnil(L, -1) || !lua_isstring(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "set_trf_encoding: inalid second argumet %s", lua_typename(L, lua_type(L, -1)));
				return 0;
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -2));
				const char* value = lua_tostring(L, -1);
				if (!(*value)) {
					DEBUGPOINT("Here Invalid value=%s\n", value);
					luaL_error(L, "set_trf_encoding: Invalid value=%s", value);
					return 0;
				}
				message.setTransferEncoding(value);
			}

			return 0;
		}

		static int get_trf_encoding(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "get_trf_encoding: inalid argumet %s", lua_typename(L, lua_type(L, -1)));
				lua_pushnil(L);
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -1));
				lua_pushstring(L, message.getTransferEncoding().c_str());
			}

			return 1;
		}

		static int set_content_type(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
				luaL_error(L, "set_content_type: inalid first argumet %s", lua_typename(L, lua_type(L, -3)));
				return 0;
			}
			else if (lua_isnil(L, -1) || !lua_isstring(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "set_content_type: inalid second argumet %s", lua_typename(L, lua_type(L, -1)));
				return 0;
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -2));
				const char* value = lua_tostring(L, -1);
				if (!(*value)) {
					DEBUGPOINT("Here Invalid value=%s\n", value);
					luaL_error(L, "set_content_type: Invalid value=%s", value);
					return 0;
				}
				message.setContentType(value);
			}

			return 0;
		}

		static int get_content_type(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "get_content_type: inalid argumet %s", lua_typename(L, lua_type(L, -1)));
				lua_pushnil(L);
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -1));
				lua_pushstring(L, message.getContentType().c_str());
			}

			return 1;
		}

		static int set_keep_alive(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
				luaL_error(L, "set_keep_alive: inalid first argumet %s", lua_typename(L, lua_type(L, -3)));
				return 0;
			}
			else if (lua_isnil(L, -1) || !lua_isboolean(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "set_keep_alive: inalid second argumet %s", lua_typename(L, lua_type(L, -1)));
				return 0;
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -2));
				const int value = lua_tointeger(L, -1);
				message.setKeepAlive(value);
			}

			return 0;
		}

		static int get_keep_alive(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "get_keep_alive: inalid argumet %s", lua_typename(L, lua_type(L, -1)));
				lua_pushnil(L);
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -1));
				lua_pushboolean(L, message.getKeepAlive());
			}

			return 1;
		}

		static int set_hdr_field(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -3) || !lua_isuserdata(L, -3)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -3)));
				luaL_error(L, "set_hdr_field: inalid first argumet %s", lua_typename(L, lua_type(L, -3)));
				return 0;
			}
			else if (lua_isnil(L, -2) || !lua_isstring(L, -2)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
				luaL_error(L, "set_hdr_field: inalid second argumet %s", lua_typename(L, lua_type(L, -2)));
				return 0;
			}
			else if (lua_isnil(L, -1) || !lua_isstring(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "set_hdr_field: inalid third argumet %s", lua_typename(L, lua_type(L, -1)));
				return 0;
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -3));
				const char* name = lua_tostring(L, -2);
				const char* value = lua_tostring(L, -1);
				if (!(*name) || !(*value)) {
					DEBUGPOINT("Here Invalid (name=%s, value =%s)\n", name, value);
					luaL_error(L, "set_hdr_field: Invalid (name=%s, value=%s)", name, value);
					return 0;
				}
				message.set(name, value);
			}

			return 0;
		}

		static int get_hdr_field(lua_State* L)
		{
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
			if (lua_isnil(L, -1) || !lua_isstring(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "get_hdr_field: inalid second argumet %s", lua_typename(L, lua_type(L, -1)));
				lua_pushnil(L);
			}
			else if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
				luaL_error(L, "get_hdr_field: inalid first argumet %s", lua_typename(L, lua_type(L, -2)));
				lua_pushnil(L);
			}
			else {
				const char* hdr_fld_name = lua_tostring(L, -1);
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -2));
				std::string hdr_fld_value = message.get(hdr_fld_name, "");
				lua_pushstring(L, hdr_fld_value.c_str());
			}

			return 1;
		}

		static int get_hdr_fields(lua_State* L)
		{
			//DEBUGPOINT("Here\n");
			EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

			if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
				DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
				luaL_error(L, "get_hdr_fields: inalid argumet %s", lua_typename(L, lua_type(L, -1)));
				lua_pushnil(L);
			}
			else {
				Net::HTTPMessage& message = *(*(Net::HTTPMessage**)lua_touserdata(L, -1));
				lua_newtable (L);
				Poco::Net::NameValueCollection::ConstIterator it = message.begin();
				Poco::Net::NameValueCollection::ConstIterator end = message.end();
				for (; it != end; ++it) {
					lua_pushstring(L, it->second.c_str());
					lua_setfield(L, -2, it->first.c_str());
				}
			}

			return 1;
		}

		namespace httpreq {
			static int parse_form(lua_State* L)
			{
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
					luaL_error(L, "parse_form: inalid argumet %s", lua_typename(L, lua_type(L, -1)));
					lua_pushnil(L);
				}
				else {
					Net::HTTPServerRequest& request = *(*(Net::HTTPServerRequest**)lua_touserdata(L, -1));
					EVLHTTPPartHandler* partHandler = new EVLHTTPPartHandler();
					Net::HTMLForm *form = NULL;
					try {
						form = new Net::HTMLForm(request, request.stream(), *partHandler);
					} catch (std::exception& ex) {
						DEBUGPOINT("CHA %s\n",ex.what());
						throw(ex);
					}
					reqHandler->addToComponents(EVLHTTPRequestHandler::html_form, form);
					reqHandler->addToComponents(EVLHTTPRequestHandler::part_handler, partHandler);

					void * ptr = lua_newuserdata(L, sizeof(Net::HTMLForm*));
					*((Net::HTMLForm**)ptr) = form;
					luaL_setmetatable(L, _html_form_type_name);
				}

				return 1;
			}

			static int get_part_names(lua_State* L)
			{
				//DEBUGPOINT("Here\n");
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

				if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
					luaL_error(L, "get_part_names: inalid argumet %s", lua_typename(L, lua_type(L, -1)));
					lua_pushnil(L);
				}
				else {
					Net::HTTPServerRequest& request = *(*(Net::HTTPServerRequest**)lua_touserdata(L, -1));
					lua_newtable(L);
					EVLHTTPPartHandler* ph = (EVLHTTPPartHandler*)reqHandler->getFromComponents(EVLHTTPRequestHandler::part_handler);
					int i = 1;
					auto parts = ph->getParts();
					for (auto it = parts.begin(); it != parts.end(); ++it, i++) {
						lua_pushstring(L, it->first.c_str());
						lua_seti(L, -2, i);
					}
				}

				return 1;
			}

			static int get_part(lua_State* L)
			{
				//DEBUGPOINT("Here\n");
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);

				if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
					luaL_error(L, "get_part: inalid first argumet %s", lua_typename(L, lua_type(L, -2)));
					lua_pushnil(L);
				}
				else if (lua_isnil(L, -1) || !lua_isstring(L, -1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
					luaL_error(L, "get_part: inalid second argumet %s", lua_typename(L, lua_type(L, -1)));
					lua_pushnil(L);
				}
				else {
					Net::HTTPServerRequest& request = *(*(Net::HTTPServerRequest**)lua_touserdata(L, -2));
					EVLHTTPPartHandler* ph = (EVLHTTPPartHandler*)reqHandler->getFromComponents(EVLHTTPRequestHandler::part_handler);
					std::string s = lua_tostring(L, -1);
				
					auto parts = ph->getParts();
					PartData * pd = parts[s];

					lua_newtable(L);

					lua_pushstring(L, "length");
					lua_pushinteger(L, pd->_length);
					lua_settable(L, -3);

					lua_pushstring(L, "type");
					lua_pushstring(L, pd->_type.c_str());
					lua_settable(L, -3);

					lua_pushstring(L, "name");
					lua_pushstring(L, pd->_name.c_str());
					lua_settable(L, -3);

					lua_pushstring(L, "data");
					lua_pushlightuserdata(L, &(pd->_cms));
					lua_settable(L, -3);

					lua_pushstring(L, "params");
					lua_newtable(L);
					for (auto it = pd->_params.begin(); it != pd->_params.end(); ++it) {
						lua_pushstring(L, it->first.c_str());
						lua_pushstring(L, it->second.c_str());
						lua_settable(L, -3);
					}
					lua_settable(L, -3);
				}

				return 1;
			}

			static int get_host(lua_State* L)
			{
				//DEBUGPOINT("Here\n");
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
					luaL_error(L, "get_host: inalid argumet %s", lua_typename(L, lua_type(L, -1)));
					lua_pushnil(L);
				}
				else {
					Net::HTTPServerRequest& request = *(*(Net::HTTPServerRequest**)lua_touserdata(L, -1));
					std::string host = request.getHost();
					lua_pushstring(L, host.c_str());
				}

				return 1;
			}

			static int get_query_parameters(lua_State* L)
			{
				//DEBUGPOINT("Here\n");
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
					luaL_error(L, "get_query_parameters: inalid argumet %s", lua_typename(L, lua_type(L, -1)));
					lua_pushnil(L);
				}
				else {
					Net::HTTPServerRequest& request = *(*(Net::HTTPServerRequest**)lua_touserdata(L, -1));
					URI::QueryParameters qp;
					try {
						URI uri(request.getURI());
						qp = uri.getQueryParameters();
					} catch (std::exception ex) {
						luaL_error(L, "%s", ex.what());
						return 0;
					}
					lua_newtable(L);
					for (auto it = qp.begin(); it != qp.end(); ++it) {
						lua_pushstring(L, it->first.c_str());
						lua_pushstring(L, it->second.c_str());
						lua_settable(L, -3);
					}
				}

				return 1;
			}

			static int get_uri(lua_State* L)
			{
				//DEBUGPOINT("Here\n");
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
					luaL_error(L, "get_uri: inalid argumet %s", lua_typename(L, lua_type(L, -1)));
					lua_pushnil(L);
				}
				else {
					Net::HTTPServerRequest& request = *(*(Net::HTTPServerRequest**)lua_touserdata(L, -1));
					std::string uri = request.getURI();
					lua_pushstring(L, uri.c_str());
				}

				return 1;
			}

			static int get_method(lua_State* L)
			{
				//DEBUGPOINT("Here\n");
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
					luaL_error(L, "get_method: inalid argumet %s", lua_typename(L, lua_type(L, -1)));
					lua_pushnil(L);
				}
				else {
					Net::HTTPServerRequest& request = *(*(Net::HTTPServerRequest**)lua_touserdata(L, -1));
					std::string method = request.getMethod();
					lua_pushstring(L, method.c_str());
				}

				return 1;
			}

			namespace htmlform {
				static int get_form_field(lua_State* L)
				{
					//DEBUGPOINT("Here\n");
					EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
					Net::HTTPServerRequest& request = reqHandler->getRequest();
					//DEBUGPOINT("Here\n");
					if (lua_isnil(L, -1) || !lua_isstring(L, -1)) {
						DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
						luaL_error(L, "get_form_field: inalid second argumet %s", lua_typename(L, lua_type(L, -1)));
						lua_pushnil(L);
					}
					else if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
						DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
						luaL_error(L, "get_form_field: inalid first argumet %s", lua_typename(L, lua_type(L, -2)));
						lua_pushnil(L);
					}
					else {
						const char* fld_name = lua_tostring(L, -1);
						Net::HTMLForm* form = NULL;
						form =  *((Net::HTMLForm**)lua_touserdata(L, -2));
						std::string fld_value = form->get(fld_name, "");
						lua_pushstring(L, fld_value.c_str());
					}

					return 1;
				}

				struct form_iterator {
					Poco::Net::NameValueCollection::ConstIterator it;
					Poco::Net::NameValueCollection::ConstIterator last;
				};

				static int begin_iteration(lua_State* L)
				{
					EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
					if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
						luaL_error(L, "begin_iteration: inalid argumet %s", lua_typename(L, lua_type(L, -1)));
						lua_pushnil(L);
						lua_pushnil(L);
						lua_pushnil(L);
					}
					else {
						Net::HTMLForm* form = NULL;
						form = *((Net::HTMLForm**)lua_touserdata(L, -1));
						struct form_iterator * iter_ptr = (struct form_iterator *)lua_newuserdata(L, sizeof(struct form_iterator));

						iter_ptr->it = form->begin();
						iter_ptr->last = form->end();
						if (iter_ptr->it == iter_ptr->last) {
							lua_pop(L, 1);
							lua_pushnil(L);
							lua_pushnil(L);
							lua_pushnil(L);
						}
						else {
							lua_pushstring(L, iter_ptr->it->first.c_str());
							lua_pushstring(L, iter_ptr->it->second.c_str());
						}
					}

					return 3;
				}

				static int next_iteration(lua_State* L)
				{
					EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
					if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
						luaL_error(L, "next_iteration: inalid second argumet %s", lua_typename(L, lua_type(L, -1)));
						lua_pushnil(L);
						lua_pushnil(L);
					}
					else if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
						luaL_error(L, "next_iteration: inalid first argumet %s", lua_typename(L, lua_type(L, -1)));
						lua_pushnil(L);
						lua_pushnil(L);
					}
					else {
						Net::HTMLForm* form = NULL;

						form = *(Net::HTMLForm**)lua_touserdata(L, -2);
						struct form_iterator * iter_ptr = (struct form_iterator *)lua_touserdata(L, -1);

						++(iter_ptr->it);
						if (iter_ptr->it == iter_ptr->last) {
							lua_pushnil(L);
							lua_pushnil(L);
						}
						else {
							lua_pushstring(L, iter_ptr->it->first.c_str());
							lua_pushstring(L, iter_ptr->it->second.c_str());
						}
					}

					return 2;
				}

				static int empty(lua_State* L)
				{
					EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
					if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
						luaL_error(L, "begin_iteration: inalid argumet %s", lua_typename(L, lua_type(L, -1)));
						lua_pushnil(L);
					}
					else {
						Net::HTMLForm* form = NULL;
						form = *((Net::HTMLForm**)lua_touserdata(L, -1));
						lua_pushboolean(L, form->empty());
					}
					return 1;
				}
			}
		}

		namespace httpresp {
			static int set_status(lua_State* L)
			{
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				Net::HTTPServerResponse& response = reqHandler->getResponse();
				if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
					luaL_error(L, "set_status: inalid first argumet %s", lua_typename(L, lua_type(L, -2)));
					return 0;
				}
				else if (lua_isnil(L, -1) || !lua_isinteger(L, -1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
					luaL_error(L, "set_status: inalid second argumet %s", lua_typename(L, lua_type(L, -1)));
					return 0;
				}
				else {
					Net::HTTPServerResponse& response = *(*(Net::HTTPServerResponse**)lua_touserdata(L, -2));
					int value = 100; lua_numbertointeger(lua_tonumber(L, -1), &value);
					response.setStatusAndReason((Net::HTTPResponse::HTTPStatus)value);
				}

				return 0;
			}

			static int set_date(lua_State* L)
			{
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				Net::HTTPServerResponse& response = reqHandler->getResponse();
				if (lua_isnil(L, -2) || !lua_isuserdata(L, -2)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -2)));
					luaL_error(L, "set_date: inalid first argumet %s", lua_typename(L, lua_type(L, -2)));
					return 0;
				}
				else if (lua_isnil(L, -1) || !lua_isstring(L, -1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
					luaL_error(L, "set_date: inalid second argumet %s", lua_typename(L, lua_type(L, -1)));
					return 0;
				}
				else {
					Net::HTTPServerResponse& response = *(*(Net::HTTPServerResponse**)lua_touserdata(L, -2));
					const char * value = lua_tostring(L, -1);
					if (!(*value)) {
						luaL_error(L, "set_date: inalid second argumet %s", lua_typename(L, lua_type(L, -2)));
						return 0;
					}
					try {
						int tzd;
						DateTime dt = DateTimeParser::parse(value, tzd);
						response.setDate(dt.timestamp());
					} catch (std::exception ex) {
						luaL_error(L, ex.what());
						return 0;
					}
				}

				return 0;
			}

			static int send(lua_State* L)
			{
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, -1) || !lua_isuserdata(L, -1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, -1)));
					luaL_error(L, "set_date: inalid argumet %s", lua_typename(L, lua_type(L, -1)));
					return 0;
				}
				else {
					Net::HTTPServerResponse& response = *(*(Net::HTTPServerResponse**)lua_touserdata(L, -1));
					std::ostream& ostr = response.send();
				}
				return 0;
			}

			static int write(lua_State* L)
			{
				EVLHTTPRequestHandler* reqHandler = get_req_handler_instance(L);
				if (lua_isnil(L, 1) || !lua_isuserdata(L, 1)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 1)));
					luaL_error(L, "ostream:write: inalid first argumet %s", lua_typename(L, lua_type(L, 1)));
					return 0;
				}
				else if (lua_isnil(L, 2) || !lua_isstring(L, 2)) {
					DEBUGPOINT("Here %s\n", lua_typename(L, lua_type(L, 2)));
					luaL_error(L, "ostream:write: inalid third argumet %s", lua_typename(L, lua_type(L, 2)));
				}
				else {
					Net::HTTPServerResponse& response = *(*(Net::HTTPServerResponse**)lua_touserdata(L, 1));
					std::ostream& ostr = response.getOStream();
					ostr << lua_tostring(L, 2);
				}
				return 0;
			}
		}
	}
}

static int evpoco_open_lua_lib(lua_State* L)
{
	static const luaL_Reg form_lib[] = {
		{ "get_form_field", &evpoco::httpmessage::httpreq::htmlform::get_form_field },
		{ "begin_iteration", &evpoco::httpmessage::httpreq::htmlform::begin_iteration},
		{ "next_iteration", &evpoco::httpmessage::httpreq::htmlform::next_iteration},
		{ "empty", &evpoco::httpmessage::httpreq::htmlform::empty},
		{ NULL, NULL }
	};

	static const luaL_Reg evpoco_httpreq_lib[] = {
		{ "set_version", &evpoco::httpmessage::set_version },
		{ "get_version", &evpoco::httpmessage::get_version },
		{ "set_chunked_trfencoding", &evpoco::httpmessage::set_chunked_trfencoding },
		{ "get_chunked_trfencoding", &evpoco::httpmessage::get_chunked_trfencoding },
		{ "set_content_length", &evpoco::httpmessage::set_content_length },
		{ "get_content_length", &evpoco::httpmessage::get_content_length },
		{ "set_trf_encoding", &evpoco::httpmessage::set_trf_encoding },
		{ "get_trf_encoding", &evpoco::httpmessage::get_trf_encoding },
		{ "set_content_type", &evpoco::httpmessage::set_content_type },
		{ "get_content_type", &evpoco::httpmessage::get_content_type },
		{ "set_keep_alive", &evpoco::httpmessage::set_keep_alive },
		{ "get_keep_alive", &evpoco::httpmessage::get_keep_alive },
		{ "get_hdr_fields", &evpoco::httpmessage::get_hdr_fields },
		{ "set_hdr_field", &evpoco::httpmessage::set_hdr_field },
		{ "get_hdr_field", &evpoco::httpmessage::get_hdr_field },
		{ "get_method", &evpoco::httpmessage::httpreq::get_method },
		{ "get_uri", &evpoco::httpmessage::httpreq::get_uri },
		{ "get_query_parameters", &evpoco::httpmessage::httpreq::get_query_parameters },
		{ "get_host", &evpoco::httpmessage::httpreq::get_host },
		{ "parse_req_form", &evpoco::httpmessage::httpreq::parse_form },
		{ "get_part_names", &evpoco::httpmessage::httpreq::get_part_names },
		{ "get_part", &evpoco::httpmessage::httpreq::get_part},
		{ NULL, NULL }
	};

	static const luaL_Reg evpoco_httpresp_lib[] = {
		{ "set_version", &evpoco::httpmessage::set_version },
		{ "get_version", &evpoco::httpmessage::get_version },
		{ "set_chunked_trfencoding", &evpoco::httpmessage::set_chunked_trfencoding },
		{ "get_chunked_trfencoding", &evpoco::httpmessage::get_chunked_trfencoding },
		{ "set_content_length", &evpoco::httpmessage::set_content_length },
		{ "get_content_length", &evpoco::httpmessage::get_content_length },
		{ "set_trf_encoding", &evpoco::httpmessage::set_trf_encoding },
		{ "get_trf_encoding", &evpoco::httpmessage::get_trf_encoding },
		{ "set_content_type", &evpoco::httpmessage::set_content_type },
		{ "get_content_type", &evpoco::httpmessage::get_content_type },
		{ "set_keep_alive", &evpoco::httpmessage::set_keep_alive },
		{ "get_keep_alive", &evpoco::httpmessage::get_keep_alive },
		{ "set_hdr_field", &evpoco::httpmessage::set_hdr_field },
		{ "get_hdr_field", &evpoco::httpmessage::get_hdr_field },
		{ "get_hdr_fields", &evpoco::httpmessage::get_hdr_fields },
		{ "set_status", &evpoco::httpmessage::httpresp::set_status },
		{ "set_date", &evpoco::httpmessage::httpresp::set_date },
		{ "send", &evpoco::httpmessage::httpresp::send },
		{ "write", &evpoco::httpmessage::httpresp::write },
		{ NULL, NULL }
	};

	static const luaL_Reg evpoco_lib[] = {
		{ "get_http_request", &evpoco::get_http_request },
		{ "get_http_response", &evpoco::get_http_response },
		{ NULL, NULL }
	};

	luaL_newlib(L, evpoco_lib); //Stack: context

	// Stack: context
	luaL_newmetatable(L, _http_req_type_name); // Stack: context meta
	luaL_newlib(L, evpoco_httpreq_lib); // Stack: context meta httpreq
	lua_setfield(L, -2, "__index"); // Stack: context meta
	lua_pushstring(L, "__gc"); // Stack: context meta "__gc"
	lua_pushcfunction(L, obj__gc); // Stack: context meta "__gc" fptr
	lua_settable(L, -3); // Stack: context meta
	lua_pop(L, 1); // Stack: context

	// Stack: context
	luaL_newmetatable(L, _http_resp_type_name); // Stack: context meta
	luaL_newlib(L, evpoco_httpresp_lib); // Stack: context meta httpresp
	lua_setfield(L, -2, "__index"); // Stack: context meta
	lua_pushstring(L, "__gc"); // Stack: context meta "__gc"
	lua_pushcfunction(L, obj__gc); // Stack: context meta "__gc" fptr
	lua_settable(L, -3); // Stack: context meta
	lua_pop(L, 1); // Stack: context

	// Stack: context
	luaL_newmetatable(L, _html_form_type_name); // Stack: context meta
	luaL_newlib(L, form_lib); // Stack: context meta form
	lua_setfield(L, -2, "__index"); // Stack: context meta
	lua_pushstring(L, "__gc"); // Stack: context meta "__gc"
	lua_pushcfunction(L, obj__gc); // Stack: context meta "__gc" fptr
	lua_settable(L, -3); // Stack: context meta
	lua_pop(L, 1); // Stack: context

	return 1;
}

EVLHTTPRequestHandler::EVLHTTPRequestHandler()
{
	_L0 = luaL_newstate();
	luaL_openlibs(_L0);

	_L = lua_newthread(_L0);
	luaL_openlibs(_L);

	lua_register(_L, "ev_yield", evpoco::evpoco_yield);
	luaL_requiref(_L, _platform_name, &evpoco_open_lua_lib, 1);

	lua_pushlightuserdata(_L, (void*) this);
	lua_setglobal(_L, "EVLHTTPRequestHandler*");
}

EVLHTTPRequestHandler::~EVLHTTPRequestHandler()
{
	lua_close(_L0);
    for ( std::map<mapped_item_type, void*>::iterator it = _components.begin(); it != _components.end(); ++it ) {
		switch (it->first) {
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
			default:
				break;
		}
    }
    _components.clear();
}

void EVLHTTPRequestHandler::send_string_response(int line_no, const char* msg)
{
	Net::HTTPServerRequest& request = (getRequest());
	Net::HTTPServerResponse& response = (getResponse());

	response.setChunkedTransferEncoding(true);
	response.setContentType("text/plain");
	std::ostream& ostr = getResponse().send();

	ostr << "EVLHTTPRequestHandler.cpp:" << line_no << ": " << msg << "\n";

	ostr.flush();
}

int EVLHTTPRequestHandler::deduceReqHandler()
{
	int status = 0;
	lua_getglobal(_L, "map_request_to_handler");
	if (lua_isnil(_L, -1)) {
		send_string_response(__LINE__, "map_request_to_handler: function not found");
		return -1;
	}
	status = lua_pcall(_L, 0, 1, 0); 
	if (LUA_OK != status) {
		DEBUGPOINT("Here %s\n", lua_tostring(_L, -1));
		return -1;
	}
	if (lua_isnil(_L, -1) || !lua_isstring(_L, -1)) {
		send_string_response(__LINE__, "map_request_to_handler: function did not return request handler");
		return -1;
	}
	_request_handler = lua_tostring(_L, -1);
	lua_pop(_L, 1);
	return 0;
}

int EVLHTTPRequestHandler::loadReqMapper()
{
	/*
	 * TBD: Caching of compiled lua files
	 * Same  _request_handler can get called again and again for multiple requests
	 * The compiled output should be cached in a static map so that
	 * Subsequent calls will be without FILE IO
	 * */
	return luaL_dofile(_L, _mapping_script.c_str());
}

int EVLHTTPRequestHandler::loadReqHandler()
{
	/*
	 * TBD: Caching of compiled lua files
	 * Same  _request_handler can get called again and again for multiple requests
	 * The compiled output should be cached in a static map so that
	 * Subsequent calls will be without FILE IO
	 * */
	return luaL_dofile(_L, _request_handler.c_str());
}

int EVLHTTPRequestHandler::handleRequest()
{
	int status = 0;
	/* Request object is necessary for deduction of script names
	 * Thus, it is not possible to do this initialization in the 
	 * constructor of this class.
	 * */
	if (INITIAL == getState()) {
		_mapping_script = getMappingScript(getRequest());
		if (0 != loadReqMapper()) {
			DEBUGPOINT("Here\n");
			send_string_response(__LINE__, lua_tostring(_L, -1));
			return PROCESSING_ERROR;
		}
		if (0 != deduceReqHandler()) {
			DEBUGPOINT("Here\n");
			return PROCESSING_ERROR;
		}
		if (0 != loadReqHandler()) {
			DEBUGPOINT("Here\n");
			send_string_response(__LINE__, lua_tostring(_L, -1));
			return PROCESSING_ERROR;
		}
		lua_getglobal(_L, "handle_request");
		if (lua_isnil(_L, -1)) {
			DEBUGPOINT("Here\n");
			send_string_response(__LINE__, "handle_request: function not found");
			return PROCESSING_ERROR;
		}
	}
	status = lua_resume(_L, NULL, 0);
	if ((LUA_OK != status) && (LUA_YIELD != status)) {
		DEBUGPOINT("HERE\n");
		std::ostream& ostr = getResponse().getOStream();
		ostr << "EVLHTTPRequestHandler.cpp:" << __LINE__ << ": " << lua_tostring(_L, -1) << "\r\n\r\n";
		ostr.flush();
		return PROCESSING_ERROR;
	}
	else if (LUA_YIELD == status) {
		DEBUGPOINT("HERE\n");
		return PROCESSING;
	}
	else {
		if (!lua_isnil(_L, -1) && lua_isstring(_L, -1)) {
			std::string output = lua_tostring(_L, -1);
			lua_pop(_L, 1);
			std::ostream& ostr = getResponse().getOStream();
			ostr << "EVLHTTPRequestHandler.cpp:" << __LINE__ << ": " << output.c_str() << "\r\n\r\n";
			ostr.flush();
		}
		/*
		else {
			send_string_response(__LINE__, "handle_request: did not return any string");
		}
		*/
		return PROCESSING_COMPLETE;
	}
}


} } // namespace Poco::EVNet
