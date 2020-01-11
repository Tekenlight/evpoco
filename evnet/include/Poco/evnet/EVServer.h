#ifndef EVNet_EVServer_INCLUDED
#define EVNet_EVServer_INCLUDED

#include "Poco/Net/Net.h"
#include "Poco/evnet/evnet.h"
#include "Poco/Net/StreamSocket.h"

namespace Poco {
namespace evnet {

class Net_API EVServer {
public:
	EVServer();
	~EVServer();
	virtual void receivedDataConsumed(int fd)=0;
	virtual void errorInReceivedData(poco_socket_t fd, bool connInErr)=0;
	virtual void dataReadyForSend(int fd)=0;
	virtual long submitRequestForConnection(int cb_evid_num,
											poco_socket_t acc_fd, Net::SocketAddress& addr, Net::StreamSocket & css)=0;
	virtual long submitRequestForHostResolution(int cb_evid_num,
											poco_socket_t acc_fd, const char* domain_name, const char* serv_name)=0;
	virtual long submitRequestForClose(poco_socket_t acc_fd, Net::StreamSocket& css)=0;
	virtual long submitRequestForSendData(poco_socket_t acc_fd, Net::StreamSocket& css)=0;
	virtual long submitRequestForRecvData(int cb_evid_num, poco_socket_t acc_fd, Net::StreamSocket& css)=0;
};

}
}

#endif
