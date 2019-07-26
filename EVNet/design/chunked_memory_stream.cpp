#include <chunked_memory_stream.h>

chunked_memory_stream::chunked_memory_stream()
{
}

// Pull out 'bytes' number of bytes from chunked_memory_stream,
// If there is less data, as many bytes as there are
// and transfer to the pointer pointed by variable buffer.
// The caller is expected to allocate memory to the buffer
//
// Returns the number of bytes Pulled out, or 0 if no data is available
// or -1 if there is any error.
int chunked_memory_stream::pull_out(void * buffer, size_t bytes)
{
	return 0;
}

// Transfers 'bytes' number of bytes to the chunked_memory_stream.
// From the memory buffer.
// The caller is expected to manage the memory for buffer.
// Returns the number of bytes transferred.
int chunked_memory_stream::push_in(void * buffer, size_t bytes)
{
	return 0;
}

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
int chunked_memory_stream::read(size_t start_pos, void *buffer, size_t bytes)
{
	return 0;
}

chunked_memory_stream::~chunked_memory_stream()
{
}

