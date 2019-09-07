#ifndef EVNet_EVServer_INCLUDED
#define EVNet_EVServer_INCLUDED

#include "Poco/Net/Net.h"
#include "Poco/EVNet/EVNet.h"
#include "Poco/Net/StreamSocket.h"

namespace Poco {
namespace EVNet {

class Net_API EVServer {
public:
	EVServer();
	~EVServer();
	virtual void receivedDataConsumed(int fd) = 0;
	virtual void errorInReceivedData(poco_socket_t fd, bool connInErr) = 0;
	virtual void dataReadyForSend(int fd) = 0;
	virtual int makeTcpConnection(poco_socket_t fd, Net::SocketAddress & addr) = 0;
};

}
}

#endif
