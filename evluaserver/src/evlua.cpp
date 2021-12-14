//
// evlua.cpp
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

#define EVLUA_PATH "EVLUA_PATH"
#define PROPERTIES_FILE "evlua.properties"

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
	virtual std::string getMappingScript(const Poco::evnet::EVServerRequest* requestPtr)
	{
		Poco::Util::AbstractConfiguration& config = Poco::Util::Application::instance().config();

		return config.getString("evlua.requestMappingScript", "mapper.lua");
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

#include <ev.h>

static void data_cb(EV_P_ ev_io *w, int revents)
{
	char buf[1024];
	errno = 0;
	memset(buf, 0, 1024);
	DEBUGPOINT("fd = [%d]\n", w->fd);
	read(w->fd, buf, 11);
	if (errno) {
		DEBUGPOINT("Error = [%s]\n", strerror(errno));
	}
	else {
		DEBUGPOINT("fd = [%d] buf = [%s]\n", w->fd, buf);
	}
}

static void * ev_lua_server(void* inp)
{
	int fd = *(int*)inp;
	ev_io stdin_watcher;
	struct ev_loop *loop = EV_DEFAULT;
	ev_io_init (&stdin_watcher, data_cb, fd, EV_READ);
	ev_io_start (loop, &stdin_watcher);

	ev_run (loop, 0);

	return (void*)0;
}

static void * server(void* inp)
{
	int fd = *(int*)inp;
	fd_set active_fd_set, read_fd_set;
	fd_set * rd_set = (fd_set *)malloc(1024 * sizeof(fd_set));
	FD_ZERO (&read_fd_set);
	//FD_SET (filedes[0], &read_fd_set);
	FD_SET (fd, rd_set);
	//int ret = select(FD_SETSIZE, &read_fd_set, NULL, NULL, NULL);
	errno = 0;
	int ret = select(1024, rd_set, NULL, NULL, NULL);
	DEBUGPOINT("ret = [%d] errno = [%d] error[%s]\n", ret, errno, strerror(errno));
	for (int i = 0; i < 1024; i++) {
		if (i == fd) {
			char buf[1024];
			errno = 0;
			memset(buf, 0, 1024);
			read(i, buf, 11);
			if (errno) {
				DEBUGPOINT("Error = [%s]\n", strerror(errno));
			}
			else {
				DEBUGPOINT("fd = [%d] buf = [%s]\n", i, buf);
			}
		}
	}

	return (void*)0;

}

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
			DEBUGPOINT("Here\n");
			loadConfiguration(PROPERTIES_FILE);
		}
		catch (...) {
			char * path_env = getenv(EVLUA_PATH);
			if (path_env) {
				std::string path(path_env);
				path = path + "/" + PROPERTIES_FILE;
				DEBUGPOINT("Here [%s]\n", path.c_str());
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
		if (_helpRequested)
		{
			displayHelp();
		}
		else
		{
			int filedes[4] = {-1, -1, -1, -1};
			if (0 != pipe(&(filedes[0]))) {
				DEBUGPOINT("Unbable create an IPC pipe [%s]\n", strerror(errno));
				return Application::EXIT_OSERR;
			}
			if (0 != pipe(&(filedes[2]))) {
				DEBUGPOINT("Unbable create an IPC pipe [%s]\n", strerror(errno));
				return Application::EXIT_OSERR;
			}
			DEBUGPOINT("FILEDES[0] = %d\n", filedes[0]);
			DEBUGPOINT("FILEDES[1] = %d\n", filedes[1]);
			DEBUGPOINT("FILEDES[2] = %d\n", filedes[2]);
			DEBUGPOINT("FILEDES[3] = %d\n", filedes[3]);
			int wr_fd = filedes[1];
			int rd_fd = filedes[2];
			HTTPServerParams *p = new HTTPServerParams();
			unsigned short port = (unsigned short) config().getInt("evlua.port", 9980);

			p->setBlocking(config().getBool("evlua.blocking", false));

			// set-up a HTTPServer instance
			EVHTTPServer srv(new EVFormRequestHandlerFactory, filedes[0], filedes[3], p);
			// start the HTTPServer
			srv.start();
			//
			/*
			pthread_t t;
			{
				pthread_attr_t attr;

				pthread_attr_init(&attr);

				//pthread_create(&t, &attr, server, filedes);
				pthread_create(&t, &attr, ev_lua_server, filedes);
			}
			*/

			DEBUGPOINT("WR fd = [%d]\n", wr_fd);
			write(wr_fd, "HELLO WORLD\n", 12); 

			char out[100] = {0};
			DEBUGPOINT("Here\n");
			int ret = read(rd_fd, out, 10);
			DEBUGPOINT("OUT = [%s] ret = [%d]\n", out, ret);

			// wait for CTRL-C or kill
			waitForTerminationRequest();
			// Stop the HTTPServer
			srv.stop();
		}
		return Application::EXIT_OK;
	}
	

private:

	bool _helpRequested;
};

int func(int argc, char ** argv)
{
	int ret = 0;
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
