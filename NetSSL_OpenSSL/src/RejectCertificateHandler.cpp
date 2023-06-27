//
// RejectCertificateHandler.cpp
//
// Library: NetSSL_OpenSSL
// Package: SSLCore
// Module:  RejectCertificateHandler
//
// Copyright (c) 2006-2009, Applied Informatics Software Engineering GmbH.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//


#include "Poco/Util/Application.h"
#include "Poco/Net/RejectCertificateHandler.h"


namespace Poco {
namespace Net {

static Poco::Util::AbstractConfiguration& appConfig()
{
	try
	{
		return Poco::Util::Application::instance().config();
	}
	catch (Poco::NullPointerException&)
	{
		throw Poco::IllegalStateException(
			"An application configuration is required to initialize the Poco::Net::SSLManager, "
			"but no Poco::Util::Application instance is available."
		);
	}
}

const std::string RejectCertificateHandler::IGNORE_CA_CERT_ERR_20("ignoreCACertErr20");
const std::string RejectCertificateHandler::CFG_OPENSSL_CA_CERT_PREFIX("OpenSSL.CACert.");

RejectCertificateHandler::RejectCertificateHandler(bool server): InvalidCertificateHandler(server)
{
}


RejectCertificateHandler::~RejectCertificateHandler()
{
}


void RejectCertificateHandler::onInvalidCertificate(const void*, VerificationErrorArgs& errorCert)
{
	Poco::Util::AbstractConfiguration& config = appConfig();
	bool ignoreErr20 = config.getBool(CFG_OPENSSL_CA_CERT_PREFIX + IGNORE_CA_CERT_ERR_20, false);

	if (errorCert.errorNumber() == 20 && ignoreErr20) {
		errorCert.setIgnoreError(true);
	}
	else {
		errorCert.setIgnoreError(false);
	}
}


} } // namespace Poco::Net
