#ifndef EVNet_EVServer_INCLUDED
#define EVNet_EVServer_INCLUDED

#include "Poco/Net/Net.h"
#include "Poco/evnet/evnet.h"
#include "Poco/Net/StreamSocket.h"

namespace Poco {
namespace evnet {

typedef void* (*generic_task_handler_t)(void*);
typedef void (*generic_task_handler_nr_t)(void*);

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
	virtual long submitRequestForTaskExecution(int cb_evid_num, poco_socket_t acc_fd, generic_task_handler_t tf, void* input_data) = 0;
	virtual long submitRequestForTaskExecutionNR(generic_task_handler_nr_t tf, void* input_data) = 0;
	virtual long notifyOnFileOpen(int cb_evid_num, poco_socket_t acc_fd, int fd) = 0;
	virtual long notifyOnFileRead(int cb_evid_num, poco_socket_t acc_fd, int fd) = 0;
};

}
}

#endif
