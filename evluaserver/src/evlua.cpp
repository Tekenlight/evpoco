//
// evlua.cpp
//
// This sample demonstrates the HTTPServer and HTMLForm classes.
//
// Tekenlight Solutions Pvt Ltd.
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

#define EVLUA_PATH "EVLUA_PATH"
#define PROPERTIES_FILE "evlua.properties"

extern "C" {
void init_so_tracker_lock();
void * pin_loaded_so(const char * libname);
}

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

class EVFormRequestHandler: public EVLHTTPRequestHandler
{
public:
	virtual std::string getMappingScript(Poco::evnet::EVServerRequest* requestPtr)
	{
		Poco::Util::AbstractConfiguration& config = Poco::Util::Application::instance().config();

		char * path_env = getenv(EVLUA_PATH);
		if (!path_env) {
			return config.getString("evlua.clMappingScript", "evlua_mapper.lua");
		}
		else {
			std::string s;
			s = s + path_env + "/" + config.getString("evlua.clMappingScript", "evlua_mapper.lua");
			return s;
		}
	}
	virtual std::string getWSMappingScript(Poco::evnet::EVServerRequest* requestPtr)
	{
		Poco::Util::AbstractConfiguration& config = Poco::Util::Application::instance().config();

		char * path_env = getenv(EVLUA_PATH);
		if (!path_env) {
			return config.getString("evlua.wsMessageMappingScript", "mapper.lua");
		}
		else {
			std::string s;
			s = s + path_env + "/" + config.getString("evlua.wsMessageMappingScript", "mapper.lua");
			return s;
		}
	}
	virtual char * getDeploymentPath()
	{
		return getenv("EVLUA_PATH");
	}
};


class EVFormRequestHandlerFactory: public EVHTTPRequestHandlerFactory
{
public:
	EVFormRequestHandlerFactory()
	{
	}

	EVHTTPRequestHandler* createRequestHandler(const Poco::evnet::EVServerRequest& request)
	{
		return new EVFormRequestHandler;
	}
};


#include <sys/select.h>
#include <pthread.h>

//#include <ev.h>

class evlua: public Poco::Util::ServerApplication
	/// The main application class to start a LUA
	/// based EVHTTP Server.
	///
	/// This class handles command-line arguments and
	/// configuration files.
	/// Start the evlua executable with the help
	/// option (/help on Windows, --help on Unix) for
	/// the available command line options.
	///
	/// To use the sample configuration file (evlua.properties),
	/// copy the file to the directory where the evlua executable
	/// resides. If you start the debug version of the evlua
	/// (evluaserverd[.exe]), you must also create a copy of the configuration
	/// file named evluaserverd.properties. In the configuration file, you
	/// can specify the port on which the server is listening (default
	/// 9980) and the format of the date/Form string sent back to the client.
	///
	/// To test the FormServer you can use any web browser (http://localhost:9980/).
{
public:
	evlua(): _helpRequested(false)
	{
	}
	
	~evlua()
	{
	}

protected:
	void initialize(Application& self)
	{
		try {
			loadConfiguration(PROPERTIES_FILE);
		}
		catch (...) {
			char * path_env = getenv(EVLUA_PATH);
			if (path_env) {
				std::string path(path_env);
				path = path + "/" + PROPERTIES_FILE;
				loadConfiguration(path); // load default configuration files, if present in path
			}
			else {
				throw ;
			}
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
		int ret = 0;
		if (_helpRequested)
		{
			displayHelp();
		}
		else
		{
			init_so_tracker_lock();
			int filedes[4] = {-1, -1, -1, -1};
			if (0 != pipe(&(filedes[0]))) {
				DEBUGPOINT("Unbable create an IPC pipe [%s]\n", strerror(errno));
				return Application::EXIT_OSERR;
			}
			if (0 != pipe(&(filedes[2]))) {
				DEBUGPOINT("Unbable create an IPC pipe [%s]\n", strerror(errno));
				return Application::EXIT_OSERR;
			}
			int wr_fd = filedes[1];
			int rd_fd = filedes[2];
			HTTPServerParams *p = new HTTPServerParams();
			unsigned short port = (unsigned short) config().getInt("evlua.port", 9980);

			p->setBlocking(config().getBool("evlua.blocking", false));

			EVHTTPServer srv(new EVFormRequestHandlerFactory, filedes[0], filedes[3], p);
			srv.start();

			size_t n = args.size();
			size_t buf_size = 1;
			for (int i = 0; i < n; i++) {
				buf_size += args[i].length() + 1;
			}
			char * buf = (char*)malloc(buf_size);
			memset(buf, 0, buf_size);
			for (int i = 0; i < n; i++) {
				if (i != 0) strcat(buf, " ");
				strcat(buf,  args[i].c_str());
			}
			strcat(buf, "\n");

			write(wr_fd, buf, strlen(buf)); 
			free(buf);
			char out[100] = {0};
			memset(out, 0, 100);
			ret = read(rd_fd, out, 99);
			ret = atoi(out);
			srv.stop();
			close(rd_fd);
			close(wr_fd);

		}
		return ret;
	}


private:

	bool _helpRequested;
};

int func(int argc, char ** argv)
{
	int ret = 0;
	if (argc < 2) {
		printf("Usage: evlua <lua_script> <arg1> <arg2> ...\n");
		return(1);
	}
	evlua app;
	ret =  app.run(argc, argv);
	return ret;
}

int main(int argc, char** argv)
{
	int ret = 0;

	ret = func(argc,argv);

	return ret;
}
