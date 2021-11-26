//
// evluaserver.cpp
//
// This sample demonstrates the HTTPServer and HTMLForm classes.
//
// Copyright (c) 2018-2019, Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/evnet/EVHTTPServer.h"
#include "Poco/evnet/EVLHTTPRequestHandler.h"
#include "Poco/evnet/EVHTTPRequestHandlerFactory.h"
#include "Poco/Net/HTTPServerParams.h"
#include "Poco/Net/HTTPServerRequest.h"
#include "Poco/Net/HTTPServerResponse.h"
#include "Poco/Net/HTTPServerParams.h"
#include "Poco/Net/PartHandler.h"
#include "Poco/Net/MessageHeader.h"
#include "Poco/Net/ServerSocket.h"
#include "Poco/CountingStream.h"
#include "Poco/NullStream.h"
#include "Poco/StreamCopier.h"
#include "Poco/Exception.h"
#include "Poco/Util/ServerApplication.h"
#include "Poco/Util/Option.h"
#include "Poco/Util/OptionSet.h"
#include "Poco/Util/HelpFormatter.h"
#include <iostream>
#include <algorithm>
#include <hiredis/hiredis.h>
#include <sys/time.h>

#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>

#include <dlfcn.h>

using Poco::Net::ServerSocket;
using Poco::evnet::EVHTTPRequestHandler;
using Poco::evnet::EVLHTTPRequestHandler;
using Poco::evnet::EVHTTPRequestHandlerFactory;
using Poco::evnet::EVHTTPServer;
using Poco::Net::HTTPServerRequest;
using Poco::Net::HTTPServerResponse;
using Poco::Net::HTTPServerParams;
using Poco::Net::MessageHeader;
using Poco::Net::NameValueCollection;
using Poco::Util::ServerApplication;
using Poco::Util::Application;
using Poco::Util::Option;
using Poco::Util::OptionSet;
using Poco::Util::HelpFormatter;
using Poco::CountingInputStream;
using Poco::NullOutputStream;
using Poco::StreamCopier;

static std::map<std::string, void*> sg_dlls;

extern "C" unsigned char *base64_encode(const unsigned char *data, size_t input_length,
								size_t *output_length, int add_line_breaks);

/*
 * This function caches loaded Shared objects in a static hashmap
 * This is called from within lua code.
 *
 * When SOs are loaded in lua they get closed as well upon lua state closure.
 * This leads to some of the function pointers and virtual methods becoming stale
 * in cached objects.
 *
 * This function is essentially used to open the same SO once again, and thus increase
 * the open count by 1, which leads to dlclose not closing the SO from memory.
 *
 */
extern "C" void * pin_loaded_so(const char * libname);
void * pin_loaded_so(const char * libname)
{
	void * lib = NULL;
	std::string name(libname);
	auto it = sg_dlls.find(name);
	if (sg_dlls.end() == it) {
		lib = dlopen(libname, RTLD_LAZY | RTLD_GLOBAL);
		if (lib) {
			sg_dlls[name] = lib;
		}
		return lib;
	}
	else {
		return it->second;
	}
}

static int sg_heart_beat_running = 1;

static void int_handler(int sig)
{
	//DEBUGPOINT("Received signal [%d]\n", sig);
}

const std::string WHITESPACE = " \n\r\t\f\v";
static std::string ltrim(const std::string &s)
{
    size_t start = s.find_first_not_of(WHITESPACE);
    return (start == std::string::npos) ? "" : s.substr(start);
}

static std::string rtrim(const std::string &s)
{
    size_t end = s.find_last_not_of(WHITESPACE);
    return (end == std::string::npos) ? "" : s.substr(0, end + 1);
}

static std::string trim(const std::string &s)
{
    return rtrim(ltrim(s));
}

typedef std::vector<std::string> modules_list_type;
static modules_list_type* get_hosted_modules()
{
	Poco::Util::AbstractConfiguration& config = Poco::Util::Application::instance().config();

	modules_list_type * m_list = new modules_list_type();
	std::string hosted_modules =  config.getString("evluaserver.hostedModules");
	DEBUGPOINT("Here hosted_modules = [%s]\n", hosted_modules.c_str());

	std::string::size_type n;
	std::string::size_type start = 0;
	std::string::size_type len = 0;
	std::string s;

	n = hosted_modules.find(",");
	while (n != std::string::npos) {
		len = n - start;
		s = trim(hosted_modules.substr(start, len));
		m_list->push_back(s);
		start = n + 1;
		n = hosted_modules.find(",", n+1);
		if (n == std::string::npos) {
			s = trim(hosted_modules.substr(start));
			m_list->push_back(s);
		}
	}

	return m_list;

}

static time_t get_min_score()
{
	struct timeval t;
	if (-1 == gettimeofday(&t, NULL)) {
		perror("Could not get timeofday");
		std::abort();
	}

	return t.tv_sec - 5;
}

static time_t get_score()
{
	struct timeval t;
	if (-1 == gettimeofday(&t, NULL)) {
		perror("Could not get timeofday");
		std::abort();
	}

	return t.tv_sec;
}

static void add_ref_range(Poco::Util::AbstractConfiguration& config, modules_list_type * m_list)
{
	redisContext *c;
	std::string config_server_host =  config.getString("evluaserver.configServerAddr");
	int config_server_port =  config.getInt("evluaserver.configServerPort");
	struct timeval timeout = { 1, 500000 };
	c = redisConnectWithTimeout(config_server_host.c_str(), config_server_port, timeout);
	if ((c == NULL) || (c->err)) {
		if (c) {
			DEBUGPOINT("Connection error: %s\n", c->errstr);
			redisFree(c);
		} else {
			DEBUGPOINT("Connection error: can't allocate redis context\n");
		}
	}
	else {
		for (std::string s : *(m_list)) {
			redisReply *reply = NULL;
			std::string redis_command;
			redis_command = std::string("ZADD ") + s + " -inf \"NEGINFINITY\""; 
			reply = (redisReply *)redisCommand(c, redis_command.c_str());
			//DEBUGPOINT("command = [%s] reply=[%lld]\n", redis_command.c_str(), reply->integer);
			if (reply) freeReplyObject(reply);
			else DEBUGPOINT("something went worng\n");

			redis_command = std::string("ZADD ") + s + " +inf \"INFINITY\""; 
			reply = (redisReply *)redisCommand(c, redis_command.c_str());
			//DEBUGPOINT("command = [%s] reply=[%lld]\n", redis_command.c_str(), reply->integer);
			if (reply) freeReplyObject(reply);
			else DEBUGPOINT("something went worng\n");
		}
		for (std::string s : *(m_list)) {
			redisReply *reply = NULL;
			std::string redis_command;
			redis_command = std::string("ZREMRANGEBYSCORE ") + s + " (-inf " + std::to_string(get_min_score());

			reply = (redisReply *)redisCommand(c, redis_command.c_str());
			char str[100];
			//DEBUGPOINT("command = [%s] reply_type = [%d] reply=[%lld]\n", redis_command.c_str(), reply->type, reply->integer);
			if (reply) freeReplyObject(reply);
			else DEBUGPOINT("something went worng\n");
			reply = NULL;
		}
	}

	return;
}

void * heart_beat(void * inputs)
{
	char * host_ip_address = (char*)inputs;
	Poco::Util::AbstractConfiguration& config = Poco::Util::Application::instance().config();
	std::string config_server_host =  config.getString("evluaserver.configServerAddr");
	int config_server_port =  config.getInt("evluaserver.configServerPort");
	int listen_port =  config.getInt("evluaserver.port");
	struct timeval timeout = { 1, 500000 };

	modules_list_type * m_list = get_hosted_modules();
	signal(SIGUSR1, int_handler);
	//DEBUGPOINT("Here\n");
	void * ret = NULL;
	struct timespec ts;

	ts.tv_sec = 4;
	ts.tv_nsec = 0;

	add_ref_range(config, m_list);

	while (sg_heart_beat_running) {
		redisContext *c;
		c = redisConnectWithTimeout(config_server_host.c_str(), config_server_port, timeout);
		if ((c == NULL) || (c->err)) {
			if (c) {
				//DEBUGPOINT("Connection error: %s\n", c->errstr);
				redisFree(c);
			} else {
				DEBUGPOINT("Connection error: can't allocate redis context\n");
			}
		}
		else {
			redisReply *reply = NULL;
			for (std::string s : *(m_list)) {
				std::string redis_command;
				redis_command += "{\"host\":\"";
				redis_command += host_ip_address;
				redis_command += "\", \"port\":";
				redis_command += std::to_string(listen_port);
				redis_command += "}";

				size_t return_length = 0;
				unsigned char * base64_encoded_arg = 
						base64_encode((const unsigned char *)redis_command.c_str(),
										(size_t)redis_command.length(), &return_length, 0);

				redis_command =
					std::string("ZADD ") + s + " " + std::to_string(get_score()) + " \"" + (char*)base64_encoded_arg + "\"";

				reply = (redisReply *)redisCommand(c, redis_command.c_str());
				//DEBUGPOINT("command = [%s] reply_type = [%d] reply=[%lld]\n", redis_command.c_str(), reply->type, reply->integer);
				if (reply) freeReplyObject(reply);
				else DEBUGPOINT("something went worng\n");
				reply = NULL;
			}
			redisFree(c);
		}
		if (sg_heart_beat_running) nanosleep(&ts, NULL);
	}

	delete m_list;
	return ret;
}

static pthread_t start_heart_beat(char * host_ip_address)
{
	pthread_t t;
	pthread_attr_t attr;

	pthread_attr_init(&attr);

	pthread_create(&t, &attr, heart_beat, host_ip_address);

	return t;
}

static void stop_heart_beat(pthread_t tid)
{
	sg_heart_beat_running = 0;
	pthread_kill(tid, SIGUSR1);
	pthread_join(tid, NULL);
	return;
}


class EVFormRequestHandler: public EVLHTTPRequestHandler
{
public:
	virtual std::string getMappingScript(const Poco::Net::HTTPServerRequest& request)
	{
		Poco::Util::AbstractConfiguration& config = Poco::Util::Application::instance().config();

		return config.getString("evluaserver.requestMappingScript", "mapper.lua");
	}
};


class EVFormRequestHandlerFactory: public EVHTTPRequestHandlerFactory
{
public:
	EVFormRequestHandlerFactory()
	{
	}

	EVHTTPRequestHandler* createRequestHandler(const HTTPServerRequest& request)
	{
		return new EVFormRequestHandler;
	}
};


class evluaserver: public Poco::Util::ServerApplication
	/// The main application class to start a LUA
	/// based EVHTTP Server.
	///
	/// This class handles command-line arguments and
	/// configuration files.
	/// Start the evluaserver executable with the help
	/// option (/help on Windows, --help on Unix) for
	/// the available command line options.
	///
	/// To use the sample configuration file (evluaserver.properties),
	/// copy the file to the directory where the evluaserver executable
	/// resides. If you start the debug version of the evluaserver
	/// (evluaserverd[.exe]), you must also create a copy of the configuration
	/// file named evluaserverd.properties. In the configuration file, you
	/// can specify the port on which the server is listening (default
	/// 9980) and the format of the date/Form string sent back to the client.
	///
	/// To test the FormServer you can use any web browser (http://localhost:9980/).
{
public:
	evluaserver(): _helpRequested(false)
	{
	}
	
	~evluaserver()
	{
	}

protected:
	void initialize(Application& self)
	{
		DEBUGPOINT("Here\n");
		if (!loadConfiguration("evluaserver.properties")) { // load default configuration files, if present in current directory
			loadConfiguration(); // load default configuration files, if present in executable directory
		}
		ServerApplication::initialize(self);
	}

	void uninitialize()
	{
		ServerApplication::uninitialize();
	}

	void defineOptions(OptionSet& options)
	{
		ServerApplication::defineOptions(options);
		
		options.addOption(
			Option("help", "h", "display help information on command line arguments")
				.required(false)
				.repeatable(false));
	}

	void handleOption(const std::string& name, const std::string& value)
	{
		ServerApplication::handleOption(name, value);

		if (name == "help")
			_helpRequested = true;
	}

	void displayHelp()
	{
		HelpFormatter helpFormatter(options());
		helpFormatter.setCommand(commandName());
		helpFormatter.setUsage("OPTIONS");
		helpFormatter.setHeader("A web server that shows how to work with HTML forms.");
		helpFormatter.format(std::cout);
	}

	int main(const std::vector<std::string>& args)
	{
		if (_helpRequested)
		{
			displayHelp();
		}
		else
		{
			HTTPServerParams *p = new HTTPServerParams();
			unsigned short port = (unsigned short) config().getInt("evluaserver.port", 9980);

			p->setBlocking(config().getBool("evluaserver.blocking", false));

			getLocalIpAddress();
			printf("Running on %s:%d\n", hostIPAddress, port);
			
			// set-up a server socket
			ServerSocket svs(port);
			// set-up a HTTPServer instance
			EVHTTPServer srv(new EVFormRequestHandlerFactory, svs, p);
			// start the HTTPServer
			srv.start();
			// wait for CTRL-C or kill
			pthread_t t = start_heart_beat(hostIPAddress);
			waitForTerminationRequest();
			// Stop the HTTPServer
			srv.stop();
			// Stop the heart_beat
			stop_heart_beat(t);
		}
		return Application::EXIT_OK;
	}
	

private:
	void getLocalIpAddress()
	{
		struct ifaddrs * ifAddrStruct=NULL;
		struct ifaddrs * ifa=NULL;
		void * tmpAddrPtr=NULL;
		memset(hostIPAddress, 0, (INET_ADDRSTRLEN+1));

		std::string prop_value = config().getString(std::string("evluaserver.networkInterfaceToRunOn"));

		getifaddrs(&ifAddrStruct);
		for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
			if (!ifa->ifa_addr) {
				continue;
			}
			if ((ifa->ifa_addr->sa_family == AF_INET) && // check it is IP4
				(!strcmp(ifa->ifa_name, prop_value.c_str()))) {
				// is a valid IP4 Address
				tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
				inet_ntop(AF_INET, tmpAddrPtr, hostIPAddress, INET_ADDRSTRLEN);
				if (ifAddrStruct!=NULL) freeifaddrs(ifAddrStruct);
				return ;
			}
		}
		if (ifAddrStruct!=NULL) freeifaddrs(ifAddrStruct);

		if (*hostIPAddress == '\0') {
			printf("Could not establish local IP address\n");
			exit(Application::EXIT_CONFIG);
		}
	}

	bool _helpRequested;
	char hostIPAddress[INET_ADDRSTRLEN+1];
};

int func(int argc, char ** argv)
{
	int ret = 0;
	evluaserver app;
	ret =  app.run(argc, argv);
	return ret;
}

int main(int argc, char** argv)
{
	int ret = 0;

	ret = func(argc,argv);

	return ret;
}
