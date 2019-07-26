#ifndef CHUNKED_MEMORY_STREAM_H_INCLUDED
#define CHUNKED_MEMORY_STREAM_H_INCLUDED

// Chunked memory Stream

#include <sys/types.h>
#include <ev_queue.h>

#define BUFFER_SIZE 4096

class chunked_memory_stream {
	// Chunked memory stream
	// This class is used for buffering data coming in from a socket 
	// One thread will read data from a socket fd and will enqueue, the
	// buffer received from socket.
	// The worker thread on the other side, will read bytes to form a full
	// request and then process the request.

public:
	chunked_memory_stream();

	int pull_out(void * buffer, size_t bytes);
	// Pull out 'bytes' number of bytes from chunked_memory_stream,
	// If there is less data, as many bytes as there are
	// and transfer to the pointer pointed by variable buffer.
	// The caller is expected to allocate memory to the buffer
	//
	// Returns the number of bytes Pulled out, or 0 if no data is available
	// or -1 if there is any error.

	int push_in(void * buffer, size_t bytes);
	// Transfers 'bytes' number of bytes to the chunked_memory_stream.
	// From the memory buffer.
	// The caller is expected to manage the memory for buffer.
	// Returns the number of bytes transferred.
	//
	
	int read(size_t start_pos, void *buffer, size_t bytes);
	// Copies 'bytes' number of bytes from the chunked_memory_stream,
	// the data is copied starting at offset '0 + start_pos'.
	// If there is less data, as many bytes as there are are copied
	// to the location pointed by buffer.
	// The caller is expected to allocate memory to the buffer.
	//
	// Differences between this and pull_out are,
	// . This method only copies the data and leaves the source unaltered
	// . This method has the ability to copy from any offset location.
	//
	// Returns the number of bytes copied, or 0 if no data is available
	// or -1 if there is any error.

	~chunked_memory_stream();

private:
	ev_queue_type buffer_list;
};

#endif

