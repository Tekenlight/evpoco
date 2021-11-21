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

#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

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

extern "C" void * open_so(const char * libname);
void * open_so(const char * libname)
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
			waitForTerminationRequest();
			// Stop the HTTPServer
			srv.stop();
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
