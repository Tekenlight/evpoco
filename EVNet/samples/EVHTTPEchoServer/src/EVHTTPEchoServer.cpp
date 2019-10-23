//
// EVHTTPEchoServer.cpp
//
// This sample demonstrates the HTTPServer and HTMLForm classes.
//
// Copyright (c) 2018-2019, Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/EVNet/EVHTTPServer.h"
#include "Poco/EVNet/EVHTTPRequestHandler.h"
#include "Poco/EVNet/EVHTTPRequestHandlerFactory.h"
#include "Poco/Net/HTTPServerParams.h"
#include "Poco/Net/HTTPServerRequest.h"
#include "Poco/Net/HTTPServerResponse.h"
#include "Poco/Net/HTTPServerParams.h"
#include "Poco/Net/HTMLForm.h"
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


using Poco::Net::ServerSocket;
using Poco::EVNet::EVHTTPRequestHandler;
using Poco::EVNet::EVHTTPRequestHandlerFactory;
using Poco::EVNet::EVHTTPServer;
using Poco::Net::HTTPServerRequest;
using Poco::Net::HTTPServerResponse;
using Poco::Net::HTTPServerParams;
using Poco::Net::MessageHeader;
using Poco::Net::HTMLForm;
using Poco::Net::NameValueCollection;
using Poco::Util::ServerApplication;
using Poco::Util::Application;
using Poco::Util::Option;
using Poco::Util::OptionSet;
using Poco::Util::HelpFormatter;
using Poco::CountingInputStream;
using Poco::NullOutputStream;
using Poco::StreamCopier;


class EVMyPartHandler: public Poco::Net::PartHandler
{
public:
	EVMyPartHandler():
		_length(0)
	{
	}
	
	void handlePart(const MessageHeader& header, std::istream& stream)
	{
		try {
		_type = header.get("Content-Type", "(unspecified)");
		if (header.has("Content-Disposition"))
		{
			std::string disp;
			NameValueCollection params;
			MessageHeader::splitParameters(header["Content-Disposition"], disp, params);
			_name = params.get("name", "(unnamed)");
			_fileName = params.get("filename", "(unnamed)");
		}
		
		CountingInputStream istr(stream);
		NullOutputStream ostr;
		StreamCopier::copyStream(istr, ostr);
		_length = istr.chars();
		} catch (std::exception& ex) {
			DEBUGPOINT("EXCEPTION HERE %s\n", ex.what());
			abort();
		}
	}

	int length() const
	{
		return _length;
	}

	const std::string& name() const
	{
		return _name;
	}

	const std::string& fileName() const
	{
		return _fileName;
	}

	const std::string& contentType() const
	{
		return _type;
	}

private:
	int _length;
	std::string _type;
	std::string _name;
	std::string _fileName;
};


class EVEcoRequestHandler: public EVHTTPRequestHandler
	/// Return a HTML document with the current date and time.
{
public:
	EVEcoRequestHandler() 
	{
	}
	
	int handleRequest()
	{
		char request_body[1024+1];
		HTTPServerRequest& request = (getRequest());
		HTTPServerResponse& response = (getResponse());
		Application& app = Application::instance();
		app.logger().information("Request from " + request.clientAddress().toString());

		memset(request_body, 0, 1025);
		std::istream & is = request.stream();
		is.get(request_body, 1024);

		response.setChunkedTransferEncoding(true);
		response.setContentType("text/plain");

		DEBUGPOINT("REQUEST BODY\n%s\n", request_body);

		std::ostream& ostr = response.send();
		//sleep(1);
		ostr.write(request_body, strlen(request_body));

		return PROCESSING_COMPLETE;
	}
};


class EVEcoRequestHandlerFactory: public EVHTTPRequestHandlerFactory
{
public:
	EVEcoRequestHandlerFactory()
	{
	}

	EVHTTPRequestHandler* createRequestHandler(const HTTPServerRequest& request)
	{
		return new EVEcoRequestHandler;
	}
};


class EVHTTPEchoServer: public Poco::Util::ServerApplication
	/// The main application class.
	///
	/// This class handles command-line arguments and
	/// configuration files.
	/// Start the EVHTTPEchoServer executable with the help
	/// option (/help on Windows, --help on Unix) for
	/// the available command line options.
	///
	/// To use the sample configuration file (EVHTTPEchoServer.properties),
	/// copy the file to the directory where the EVHTTPEchoServer executable
	/// resides. If you start the debug version of the EVHTTPEchoServer
	/// (EVHTTPEchoServerd[.exe]), you must also create a copy of the configuration
	/// file named EVHTTPEchoServerd.properties. In the configuration file, you
	/// can specify the port on which the server is listening (default
	/// 9980) and the format of the date/Form string sent back to the client.
	///
	/// To test the FormServer you can use any web browser (http://localhost:9980/).
{
public:
	EVHTTPEchoServer(): _helpRequested(false)
	{
	}
	
	~EVHTTPEchoServer()
	{
	}

protected:
	void initialize(Application& self)
	{
		loadConfiguration(); // load default configuration files, if present
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
			unsigned short port = (unsigned short) config().getInt("EVHTTPEchoServer.port", 9980);

			p->setBlocking(config().getBool("EVHTTPEchoServer.blocking", false));
			
			// set-up a server socket
			ServerSocket svs(port);
			// set-up a HTTPServer instance
			EVHTTPServer srv(new EVEcoRequestHandlerFactory, svs, p);
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
	bool _helpRequested;
};

int func(int argc, char ** argv)
{
	int ret = 0;
	EVHTTPEchoServer app;
	ret =  app.run(argc, argv);
	return ret;
}

int main(int argc, char** argv)
{
	int ret = 0;

	ret = func(argc,argv);

	return ret;
}
