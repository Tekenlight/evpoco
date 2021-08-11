extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}


#include "Poco/Net/SecureStreamSocket.h"
#include "Poco/Net/SSLManager.h"

const static char *_stream_socket_type_name = "streamsocket";

static int connect_TLS(lua_State* L)
{
	Poco::Net::StreamSocket * ss_ptr = *(Poco::Net::StreamSocket **)luaL_checkudata(L, 1, _stream_socket_type_name);
	const char * peer_name = lua_tostring(L, 2);
	Poco::Net::Context::Ptr pContext = Poco::Net::SSLManager::instance().defaultClientContext();
	if (peer_name) {
		Poco::Net::SecureStreamSocket sss(Poco::Net::SecureStreamSocket::attach(*ss_ptr, std::string(peer_name), pContext));
		*ss_ptr = sss;
	}
	else {
		Poco::Net::SecureStreamSocket sss(Poco::Net::SecureStreamSocket::attach(*ss_ptr, pContext));
		*ss_ptr = sss;
	}
	return 0;
}


extern "C" int luaopen_libevlnetssl(lua_State *L);
int luaopen_libevlnetssl(lua_State *L)
{
	static const luaL_Reg lua_netssl_methods[] = {
		{ "connect_TLS", connect_TLS}
		,{NULL, NULL}
	};

	luaL_newlib(L, lua_netssl_methods);


	return 1;    
}

