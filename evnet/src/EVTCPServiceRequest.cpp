//
// EVTCPServiceRequest.cpp
//
// Library: evnet
// Package: EVTCPServer
// Module:  EVTCPServer
//
// Tekenlight Solutions Pvt Ltd.
// and Contributors.
//
// SPDX-License-Identifier:	BSL-1.0
//

#include "Poco/evnet/evnet.h"
#include "Poco/evnet/EVTCPServiceRequest.h"

using Poco::Net::StreamSocket;

namespace Poco{ namespace evnet {

EVTCPServiceRequest& EVTCPServiceRequest::operator = (const EVTCPServiceRequest& from)
{
	this->_sr_num = from._sr_num;
	this->_cb_evid_num = from._cb_evid_num;
	this->_acc_fd = from._acc_fd;
	this->_domain_name = from._domain_name;
	this->_addr = from._addr;
	this->_serv_name = from._serv_name;
	this->_task_func = from._task_func;
	this->_task_input_data = from._task_input_data;
	this->_file_fd = from._file_fd;
	this->_poll_for = from._poll_for;
	this->_poll_for_fd = from._poll_for_fd;
	this->_conn_socket_managed = from._conn_socket_managed;
	this->_event = from._event;
	this->_ssp = from._ssp;
	this->_time_out_for_oper = from._time_out_for_oper;
	this->_cn = from._cn;
	return *this;
}

EVTCPServiceRequest::EVTCPServiceRequest(const EVTCPServiceRequest& from):
	_sr_num(from._sr_num),
	_cb_evid_num(from._cb_evid_num),
	_acc_fd(from._acc_fd),
	_domain_name(from._domain_name),
	_addr(from._addr),
	_serv_name(from._serv_name),
	_task_func(from._task_func),
	_task_input_data(from._task_input_data),
	_file_fd(from._file_fd),
	_poll_for(from._poll_for),
	_poll_for_fd(from._poll_for_fd),
	_conn_socket_managed(from._conn_socket_managed),
	_event(from._event),
	_ssp(from._ssp),
	_time_out_for_oper(-1),
	_cn(0)
{
}

EVTCPServiceRequest::EVTCPServiceRequest(long sr_num, what event, poco_socket_t acc_fd, Net::StreamSocket& ss):
	_sr_num(sr_num),
	_cb_evid_num(0),
	_acc_fd(acc_fd),
	_event(event),
	_domain_name(0),
	_serv_name(0),
	_task_func(0),
	_task_input_data(0),
	_file_fd(-1),
	_poll_for(0),
	_poll_for_fd(-1),
	_conn_socket_managed(0),
	_ssp(&ss),
	_time_out_for_oper(-1),
	_cn(0)
{
}

EVTCPServiceRequest::EVTCPServiceRequest(long sr_num, int cb_evid_num, what event, poco_socket_t acc_fd, Net::StreamSocket& ss):
	_sr_num(sr_num),
	_cb_evid_num(cb_evid_num),
	_acc_fd(acc_fd),
	_event(event),
	_domain_name(0),
	_serv_name(0),
	_task_func(0),
	_task_input_data(0),
	_file_fd(-1),
	_poll_for(0),
	_poll_for_fd(-1),
	_conn_socket_managed(0),
	_ssp(&ss),
	_time_out_for_oper(-1),
	_cn(0)
{
}

EVTCPServiceRequest::EVTCPServiceRequest(long sr_num, int cb_evid_num, what event, poco_socket_t acc_fd, int file_fd):
	_sr_num(sr_num),
	_cb_evid_num(cb_evid_num),
	_event(event),
	_acc_fd(acc_fd),
	_domain_name(0),
	_serv_name(0),
	_task_func(0),
	_task_input_data(0),
	_file_fd(file_fd),
	_poll_for(0),
	_poll_for_fd(-1),
	_conn_socket_managed(0),
	_time_out_for_oper(-1),
	_cn(0)
{
}

EVTCPServiceRequest::EVTCPServiceRequest(long sr_num, int cb_evid_num, what event, poco_socket_t acc_fd,
											Net::StreamSocket& ss, Net::SocketAddress& addr):
	_sr_num(sr_num),
	_cb_evid_num(cb_evid_num),
	_acc_fd(acc_fd),
	_domain_name(0),
	_addr(addr),
	_serv_name(0),
	_task_func(0),
	_task_input_data(0),
	_file_fd(-1),
	_poll_for(0),
	_poll_for_fd(-1),
	_conn_socket_managed(0),
	_event(event),
	_ssp(&ss),
	_time_out_for_oper(-1),
	_cn(0)
{
}

EVTCPServiceRequest::EVTCPServiceRequest(long sr_num, int cb_evid_num, what event, poco_socket_t acc_fd,
											 const char* domain_name, const char* serv_name):
	_sr_num(sr_num),
	_cb_evid_num(cb_evid_num),
	_acc_fd(acc_fd),
	_event(event),
	_domain_name(domain_name),
	_serv_name(serv_name),
	_task_func(0),
	_task_input_data(0),
	_file_fd(-1),
	_poll_for(0),
	_poll_for_fd(-1),
	_conn_socket_managed(0),
	_time_out_for_oper(-1),
	_cn(0)
{
}

EVTCPServiceRequest::EVTCPServiceRequest(long sr_num, int cb_evid_num, what event, poco_socket_t acc_fd,
											 task_func_with_return_t tf, void* td):
	_sr_num(sr_num),
	_cb_evid_num(cb_evid_num),
	_acc_fd(acc_fd),
	_event(event),
	_domain_name(0),
	_serv_name(0),
	_task_func(tf),
	_task_input_data(td),
	_file_fd(-1),
	_poll_for(0),
	_poll_for_fd(-1),
	_conn_socket_managed(0),
	_time_out_for_oper(-1),
	_cn(0)
{
}

EVTCPServiceRequest::EVTCPServiceRequest(long sr_num, int cb_evid_num, what event, poco_socket_t acc_fd, void * data):
	_sr_num(sr_num),
	_cb_evid_num(cb_evid_num),
	_acc_fd(acc_fd),
	_event(event),
	_domain_name(0),
	_serv_name(0),
	_task_func(0),
	_task_input_data(data),
	_file_fd(-1),
	_poll_for(0),
	_poll_for_fd(-1),
	_conn_socket_managed(0),
	_time_out_for_oper(-1),
	_cn(0)
{
}

EVTCPServiceRequest::~EVTCPServiceRequest()
{
}

} } // namespace evnet and Poco end.
