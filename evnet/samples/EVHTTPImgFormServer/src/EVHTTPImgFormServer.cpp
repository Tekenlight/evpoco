//
// EVHTTPImgFormServer.cpp
//
// This sample demonstrates the HTTPServer and HTMLForm classes.
//
// Copyright (c) 2018-2019, Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//

#include <ef_io.h>

#include "Poco/evnet/EVHTTPServer.h"
#include "Poco/evnet/EVHTTPRequestHandler.h"
#include "Poco/evnet/EVHTTPRequestHandlerFactory.h"
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
using Poco::evnet::EVHTTPRequestHandler;
using Poco::evnet::EVHTTPRequestHandlerFactory;
using Poco::evnet::EVHTTPServer;
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

class EVFormRequestHandler: public EVHTTPRequestHandler
	/// Return a HTML document with the current date and time.
{
public:
	struct addrinfo * addr_info = NULL;
	int c_fd1 = -1;
	int c_fd2 = -1;
	int c_i = 0;
	char buf[4097];
	EVFormRequestHandler() 
	{
	}

	~EVFormRequestHandler()
	{
		if (c_fd1>-1) ef_close(c_fd1);
		if (c_fd2>-1) ef_close(c_fd2);
	}

	void send_string_response(int line_no, const char* msg)
	{
		Poco::Net::HTTPServerRequest& request = (getRequest());
		Poco::Net::HTTPServerResponse& response = (getResponse());

		response.setChunkedTransferEncoding(true);
		response.setContentType("text/plain");
		response.setContentType("text/plain");
		response.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
		std::ostream& ostr = getResponse().send();

		ostr << __FILE__ <<":" << line_no << ": " << msg << "\n";

		ostr.flush();
	}

	void send_error_response(int line_no)
	{
		HTTPServerRequest& request = (getRequest());
		HTTPServerResponse& response = (getResponse());


		std::ostream& ostr = getResponse().getOStream();

		ostr <<
			"<html>\n"
			"<head>\n"
			"<title>EVHTTPImgFormServer getaddrinfo Processing ERROR</title>\n"
			"</head>\n"
			"<body>\n"
			"<h1>EVHTTP Form Server Sample</h1>\n";

		ostr << line_no << ":" << "COULD NOT RESOLVE HOST\n";

		ostr << "</body>\n";
		ostr << "</html>\n";
		ostr.flush();
	}

	int handleRequest1()
	{
		HTTPServerRequest& request = (getRequest());
		HTTPServerResponse& response = (getResponse());
		Application& app = Application::instance();
		app.logger().information("Request from " + request.clientAddress().toString());

		EVMyPartHandler partHandler;
		HTMLForm *form1 = NULL;
		try {
		form1 = new HTMLForm(request, request.stream(), partHandler);
		} catch (std::exception& ex) {
			DEBUGPOINT("CHA %s\n",ex.what());
			throw(ex);
		}

		//HTMLForm form(request, request.stream(), partHandler);
		HTMLForm& form = *form1;
		response.setChunkedTransferEncoding(true);
		response.setContentType("text/html");
		std::ostream& ostr = response.send();

		Poco::evnet::EVUpstreamEventNotification &usN = getUNotification();
		if (usN.getRet() != 0) {
			send_error_response(__LINE__);
			return -1;
		}

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
			
		if (!addr_info) ostr << "NO ADDRESS FOUND\n";
		int i = 0;
		struct addrinfo *p;
		char host[256];

		for (p = addr_info; p; p = p->ai_next) {
			i++;
			getnameinfo(p->ai_addr, p->ai_addrlen, host, sizeof (host), NULL, 0, NI_NUMERICHOST);
			ostr << "<p>";
			ostr << i << ".";
			ostr << "&nbsp&nbsp" <<  host;
			ostr << "&nbsp&nbsp" <<  p->ai_addrlen;
			for (int i = 0; i < p->ai_addrlen; i++) {
				char s[512];
				unsigned char c = p->ai_addr->sa_data[i];
				if (!i) sprintf(s,"&nbsp&nbsp%X", c);
				else sprintf(s,":%X", c);
				ostr << s;
			}
			if (p->ai_addr->sa_family == AF_INET) ostr << "&nbsp&nbspIPV4 ADDRESS";
			else ostr << "&nbsp&nbspIPV6 ADDRESS";
			ostr << "</p>";
		}

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
		ostr.flush();

		delete form1;
		return PROCESSING_COMPLETE;
	}

	int handleRequestOne()
	{
		resolveHost(std::bind(&EVFormRequestHandler::handleRequest1, this), "localhost", NULL, &addr_info);
		return PROCESSING;
	}

	int handleRequestZero()
	{
		Poco::evnet::EVUpstreamEventNotification &usN = getUNotification();
		if (usN.getRet() < 0) {
			DEBUGPOINT("Here ret = %zd, errno = %d\n", usN.getRet(), usN.getErrNo());
			send_string_response(__LINE__, strerror(usN.getErrNo()));
			return PROCESSING_COMPLETE;
		}
		if (usN.getRet() == 0) {
			//DEBUGPOINT("Reached end of file\n");
			return handleRequestOne();
		}
		int ret =0;
		while ((ret = ef_read(c_fd1, buf, 4096)) > 0) {
			//DEBUGPOINT("Got some bytes %d\n", ret);
		}
		if (ret == -1 && errno != EAGAIN) {
			send_string_response(__LINE__, strerror(errno));
			return PROCESSING_ERROR;
		}
		else if (ret == 0) {
			//DEBUGPOINT("Reached end of file\n");
			return handleRequestOne();
		}
		pollFileReadStatus(std::bind(&EVFormRequestHandler::handleRequestZero, this), c_fd1);
		return PROCESSING;
	}

	int handleRequest0()
	{
		Poco::evnet::EVUpstreamEventNotification &usN = getUNotification();
		if (usN.getRet() < 0) {
			send_string_response(__LINE__, strerror(usN.getErrNo()));
			return PROCESSING_COMPLETE;
		}
		memset(buf, 0, 4097);
		int ret = ef_read(c_fd1, buf, 4096);
		if (ret == -1 && errno != EAGAIN) {
			send_string_response(__LINE__, strerror(errno));
			return PROCESSING_ERROR;
		}
		else if (ret == 0) {
			DEBUGPOINT("Reached end of file\n");
			send_string_response(__LINE__, " Empty file");
			return PROCESSING_ERROR;
		}
		pollFileReadStatus(std::bind(&EVFormRequestHandler::handleRequestZero, this), c_fd1);
		return PROCESSING;
	}

	int handleRequest()
	{
		c_fd1 = ef_open("./Sudheer.JPG", O_RDONLY);
		if (c_fd1 == -1) {
			send_string_response(__LINE__, strerror(errno));
			return PROCESSING_ERROR;
		}
		pollFileOpenStatus(std::bind(&EVFormRequestHandler::handleRequest0, this), c_fd1);
		return PROCESSING;
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


class EVHTTPImgFormServer: public Poco::Util::ServerApplication
	/// The main application class.
	///
	/// This class handles command-line arguments and
	/// configuration files.
	/// Start the EVHTTPImgFormServer executable with the help
	/// option (/help on Windows, --help on Unix) for
	/// the available command line options.
	///
	/// To use the sample configuration file (EVHTTPImgFormServer.properties),
	/// copy the file to the directory where the EVHTTPImgFormServer executable
	/// resides. If you start the debug version of the EVHTTPImgFormServer
	/// (EVHTTPImgFormServerd[.exe]), you must also create a copy of the configuration
	/// file named EVHTTPImgFormServerd.properties. In the configuration file, you
	/// can specify the port on which the server is listening (default
	/// 9980) and the format of the date/Form string sent back to the client.
	///
	/// To test the FormServer you can use any web browser (http://localhost:9980/).
{
public:
	EVHTTPImgFormServer(): _helpRequested(false)
	{
	}
	
	~EVHTTPImgFormServer()
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
			unsigned short port = (unsigned short) config().getInt("EVHTTPImgFormServer.port", 9980);

			p->setBlocking(config().getBool("EVHTTPImgFormServer.blocking", false));
			
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
	EVHTTPImgFormServer app;
	ret =  app.run(argc, argv);
	return ret;
}

int main(int argc, char** argv)
{
	int ret = 0;

	ret = func(argc,argv);

	return ret;
}
