//
// EVServerResponse.h
//
// Library: evnet
// Package: HTTPServer
// Module:  EVServerResponse
//
// Definition of the EVServerResponse class.
//
//


#ifndef EVNet_EVServerResponse_INCLUDED
#define EVNet_EVServerResponse_INCLUDED
#include "Poco/Net/Net.h"


namespace Poco {
namespace evnet {

class Net_API EVServerResponse
	/// This is a marker class for any server reuqest
	/// representing server-side requests.
	///
{
public:
	EVServerResponse();
		/// Creates the EVServerResponse, using the
		/// given EVServerSession.

	~EVServerResponse();
		/// Destroys the EVServerResponse.
		
};

} } // namespace Poco::evnet


#endif // EVNet_EVServerRequest_INCLUDED
