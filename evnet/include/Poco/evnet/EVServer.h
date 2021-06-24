#ifndef EVNet_EVServer_INCLUDED
#define EVNet_EVServer_INCLUDED

#include "Poco/Net/Net.h"
#include "Poco/evnet/evnet.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/evnet/EVAcceptedSocket.h"

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
											EVAcceptedSocket *tn, Net::SocketAddress& addr, Net::StreamSocket & css)=0;
	virtual long submitRequestForPoll(int cb_evid_num, EVAcceptedSocket *tn, Net::StreamSocket & css, int poll_for)=0;
	virtual long submitRequestForHostResolution(int cb_evid_num,
											EVAcceptedSocket *tn, const char* domain_name, const char* serv_name)=0;
	virtual long submitRequestForClose(EVAcceptedSocket *tn, Net::StreamSocket& css)=0;
	virtual long submitRequestForSendData(EVAcceptedSocket *tn, Net::StreamSocket& css)=0;
	virtual long submitRequestForRecvData(int cb_evid_num, EVAcceptedSocket *tn, Net::StreamSocket& css)=0;
	virtual long submitRequestForTaskExecution(int cb_evid_num, EVAcceptedSocket *tn, generic_task_handler_t tf, void* input_data) = 0;
	virtual long submitRequestForTaskExecutionNR(generic_task_handler_nr_t tf, void* input_data) = 0;
	virtual long notifyOnFileOpen(int cb_evid_num, EVAcceptedSocket *tn, int fd) = 0;
	virtual long notifyOnFileRead(int cb_evid_num, EVAcceptedSocket *tn, int fd) = 0;
};

}
}

#endif
