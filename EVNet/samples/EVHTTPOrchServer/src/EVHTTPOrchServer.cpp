//
// EVHTTPOrchServer.cpp
//
// This sample demonstrates the HTTPServer and HTMLForm classes.
//
// Copyright (c) 2018-2019, Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//

#include <iostream>

#include "Poco/Net/StreamSocket.h"
#include "Poco/EVNet/EVHTTPServer.h"
#include "Poco/EVNet/EVHTTPRequestHandler.h"
#include "Poco/EVNet/EVHTTPRequestHandlerFactory.h"
#include "Poco/EVNet/EVHTTPClientSession.h"
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


#include "Poco/EVNet/EVHTTPRequest.h"

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
using Poco::Net::HTTPRequest;
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


class EVFormRequestHandler: public EVHTTPRequestHandler
	/// Return a HTML document with the current date and time.
{
private:
	static const int PART_ONE = 1;
	static const int PART_TWO = 2;
	static const int PART_THREE = 3;
	static const int FINAL = 4;

	EVMyPartHandler partHandler;
	HTMLForm *form1 = NULL;
	Poco::EVNet::EVHTTPClientSession session;

	void init()
	{
		Application::instance().logger().information("Request from " + getRequest().clientAddress().toString());
		try {
			form1 = new HTMLForm((getRequest()), getRequest().stream(), partHandler);
		} catch (std::exception& ex) {
			DEBUGPOINT("CHA %s\n",ex.what());
			throw(ex);
		}

		getResponse().setChunkedTransferEncoding(true);
		getResponse().setContentType("text/html");

		getResponse().send();
	}

	int part_one()
	{
		SocketAddress address("127.0.0.1", 9980);
		StreamSocket ss;
		session.setSS(ss);
		session.setAddr(address);
		if (0 > makeNewHTTPConnection(PART_TWO, &session)) {
			send_error_response();
			return -1;
		}

		return 0;

	}

	int part_two()
	{
		Poco::EVNet::EVUpstreamEventNotification &usN = getUNotification();
		DEBUGPOINT("Socket = %d Refcount = %d state = %d\n", usN.sockfd(), session.getSS().impl()->referenceCount(), session.getState());
		DEBUGPOINT("Service Request Number = %ld\n", usN.getSRNum());
		if (usN.getBytes() < 0) {
			send_error_response();
			return -1;
		}
		Poco::EVNet::EVHTTPRequest request(HTTPRequest::HTTP_POST, "http://localhost:9980/echo");
		request.setHost("localhost:9980");
		std::string body("this is a random request body");
		request.setContentLength((int) body.length());
		sendHTTPHeader(session, request);
		*(request.getRequestStream()) << body;
		sendHTTPRequestData(session, request);

		sleep(1);
		return part_three();
	}

	int part_three()
	{
		HTTPServerRequest& request = (getRequest());
		HTTPServerResponse& response = (getResponse());


		HTMLForm& form = *form1;

		std::ostream& ostr = getResponse().getOStream();

		ostr <<
			"<html>\n"
			"<head>\n"
			"<title>POCO Form Server Sample</title>\n"
			"</head>\n"
			"<body>\n"
			"<h1>POCO Form Server Sample</h1>\n"
			"<h2>GET Form</h2>\n"
			"<form method=\"GET\" action=\"/form\">\n"
			"<input type=\"text\" name=\"text\" size=\"31\">\n"
			"<input type=\"submit\" value=\"GET\">\n"
			"</form>\n"
			"<h2>POST Form</h2>\n"
			"<form method=\"POST\" action=\"/form\">\n"
			"<input type=\"text\" name=\"text\" size=\"31\">\n"
			"<input type=\"submit\" value=\"POST\">\n"
			"</form>\n"
			"<h2>File Upload</h2>\n"
			"<form method=\"POST\" action=\"/form\" enctype=\"multipart/form-data\">\n"
			"<input type=\"file\" name=\"file\" size=\"31\"> \n"
			"<input type=\"submit\" value=\"Upload\">\n"
			"</form>\n";
			
		ostr << "<h2>Request</h2><p>\n";
		ostr << "Method: " << request.getMethod() << "<br>\n";
		ostr << "URI: " << request.getURI() << "<br>\n";
		NameValueCollection::ConstIterator it = request.begin();
		NameValueCollection::ConstIterator end = request.end();
		for (; it != end; ++it)
		{
			ostr << it->first << ": " << it->second << "<br>\n";
		}
		ostr << "</p>";

		if (!form.empty())
		{
			ostr << "<h2>Form</h2><p>\n";
			it = form.begin();
			end = form.end();
			for (; it != end; ++it)
			{
				ostr << it->first << ": " << it->second << "<br>\n";
			}
			ostr << "</p>";
		}

		if (!partHandler.name().empty())
		{
			ostr << "<h2>Upload</h2><p>\n";
			ostr << "Name: " << partHandler.name() << "<br>\n";
			ostr << "File Name: " << partHandler.fileName() << "<br>\n";
			ostr << "Type: " << partHandler.contentType() << "<br>\n";
			ostr << "Size: " << partHandler.length() << "<br>\n";
			ostr << "</p>";
		}
		ostr << "</body>\n";
		ostr << "</html>\n";
		ostr.flush();

		return 0;

	}

	void send_error_response()
	{
		HTTPServerRequest& request = (getRequest());
		HTTPServerResponse& response = (getResponse());


		HTMLForm& form = *form1;

		std::ostream& ostr = getResponse().getOStream();

		ostr <<
			"<html>\n"
			"<head>\n"
			"<title>EVHTTPOrchServer Processing ERROR</title>\n"
			"</head>\n"
			"<body>\n"
			"<h1>EVHTTP Form Server Sample</h1>\n";

		ostr << "COULD NOT OPEN CONNECTION WITH DATA PROVIDER\n";

		ostr << "</body>\n";
		ostr << "</html>\n";
		ostr.flush();
	}

	void cleanup()
	{
		if (form1) delete form1;
		//if (ostr_ptr) delete ostr_ptr;
	}

public:
	EVFormRequestHandler() 
	{
	}

	virtual ~EVFormRequestHandler() 
	{
		cleanup();
	}

	int handleRequest()
	{
		int return_value = PROCESSING;
		switch (getEvent()) {
			case INITIAL:
				init();
			case PART_ONE:
				if (0 > part_one()) {
					DEBUGPOINT("Here\n");
					return_value = PROCESSING_ERROR;
				}
				break;
			case PART_TWO:
				if (0> part_two()) {
					DEBUGPOINT("Here\n");
				 	return_value = PROCESSING_ERROR;
				}
				else {
					DEBUGPOINT("Here\n");
					return_value = PROCESSING_COMPLETE;
				}
				break;
			case PART_THREE:
				return_value = PROCESSING_COMPLETE;
				break;
			default:
				std::abort();
		}
		return return_value;
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


class EVHTTPOrchServer: public Poco::Util::ServerApplication
	/// The main application class.
	///
	/// This class handles command-line arguments and
	/// configuration files.
	/// Start the EVHTTPOrchServer executable with the help
	/// option (/help on Windows, --help on Unix) for
	/// the available command line options.
	///
	/// To use the sample configuration file (EVHTTPOrchServer.properties),
	/// copy the file to the directory where the EVHTTPOrchServer executable
	/// resides. If you start the debug version of the EVHTTPOrchServer
	/// (EVHTTPOrchServerd[.exe]), you must also create a copy of the configuration
	/// file named EVHTTPOrchServerd.properties. In the configuration file, you
	/// can specify the port on which the server is listening (default
	/// 9980) and the format of the date/Form string sent back to the client.
	///
	/// To test the FormServer you can use any web browser (http://localhost:9980/).
{
public:
	EVHTTPOrchServer(): _helpRequested(false)
	{
	}
	
	~EVHTTPOrchServer()
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
			unsigned short port = (unsigned short) config().getInt("EVHTTPOrchServer.port", 9981);

			p->setBlocking(config().getBool("EVHTTPOrchServer.blocking", false));
			
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
	bool _helpRequested;
};

int func(int argc, char ** argv)
{
	int ret = 0;
	EVHTTPOrchServer app;
	ret =  app.run(argc, argv);
	return ret;
}

int main(int argc, char** argv)
{
	int ret = 0;

	ret = func(argc,argv);

	return ret;
}
