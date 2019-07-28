#include <chunked_memory_stream.h>
#include <string.h>

chunked_memory_stream::chunked_memory_stream()
{
}

// Transfers 'bytes' number of bytes to the chunked_memory_stream.
// From the memory buffer.
// The caller is expected to manage the memory for buffer.
// Returns the number of bytes transferred.
int chunked_memory_stream::push(void * buffer, size_t bytes)
{
	_buffer_list.add_node(buffer,bytes);
	return 0;
}

// Copies 'bytes' number of bytes from the chunked_memory_stream,
// the data is copied starting at offset '0 + start_pos'.
// If there is less data, as many bytes as there are are copied
// to the location pointed by buffer.
// The caller is expected to allocate memory to the buffer.
//
// The index start_pos is C style, i.e. first character is at 0th
// position.
//
// Differences between this and pull_out are,
// . This method only copies the data and leaves the source unaltered
// . This method has the ability to copy from any offset location.
//
// Returns the number of bytes copied, or 0 if no data is available
// or -1 if there is any error.
size_t chunked_memory_stream::read(size_t start_pos, void *buffer, size_t bytes)
{
	memory_buffer_list::node * node_ptr = 0;
	void * node_buffer = 0;
	size_t to_be_copied = 0;
	size_t copied = 0;
	size_t traversed = 0; // Traversed indicates count and not index.
	size_t start_pos_in_node = 0;

	node_ptr = _buffer_list.get_head();
	while (node_ptr) {
		// First reach the node to start copying from
		if ((start_pos - traversed) >= node_ptr->get_buffer_len()) {
			traversed += node_ptr->get_buffer_len();
			node_ptr = _buffer_list.get_next(node_ptr);
			continue;
		}
		// offset within the node
		//
		// 01->23->45->67
		// traversed can be 0, or 2, or 4, or 6
		// if start_pos is, say 4, traversed will be 4 (2 +2)
		// start_pos_in_node is this case should be 0 (= 4 - 4)
		//
		// If start_pos is 5 start_pos_in_node should be 1 and will be
		// (= 5 - 4).
		// start_pos_in_node is also an index variable
		// Thus starts from 0
		start_pos_in_node = start_pos - traversed;
		traversed += start_pos_in_node;
		break;
	}

	// Start position is beyond the total buffer.
	if (!node_ptr) return -1;

	// copy as much data required.
	while (node_ptr && copied < bytes) {
		to_be_copied = 0; // To be copied from the current node.

		// => start_pos is within this buffer.
		if ((bytes - copied) >= (node_ptr->get_buffer_len() - start_pos_in_node)) {
			// remaining to be copied exceeds the buffer len.
			// Copy what can be taken from the buffer.
			to_be_copied = node_ptr->get_buffer_len() - start_pos_in_node;
		}
		else {
			// remaining to be copied is not exceeding the buffer len.
			to_be_copied = bytes - copied;
		}
		node_buffer = node_ptr->get_buffer();
		memcpy(((char*)buffer + copied), ((char*)node_buffer + start_pos_in_node)  , to_be_copied);

		copied += to_be_copied;
		// Next buffer onwards offset to copy from will be from
		// begining.
		start_pos_in_node = 0;
		node_ptr = _buffer_list.get_next(node_ptr);
	}
	return copied;
}

// Moves the head of the data stream to the offset 0 + bytes
// Memory holding the data is freed.
// Returns the number of bytes erased.
size_t chunked_memory_stream::erase(size_t bytes)
{
	memory_buffer_list::node * node_ptr = 0;
	void * node_buffer = 0;
	size_t to_be_erased = 0;
	size_t erased = 0;
	size_t buffer_len = 0;

	to_be_erased = bytes;
	node_ptr = _buffer_list.get_head();
	while (to_be_erased && node_ptr) {
		// First reach the node to start copying from
		if (to_be_erased >= node_ptr->get_buffer_len()) {
			to_be_erased -= node_ptr->get_buffer_len();
			erased += node_ptr->get_buffer_len();
			_buffer_list.pop_head();
			node_ptr = _buffer_list.get_head();
			continue;
		}

		buffer_len = node_ptr->get_buffer_len();
		node_buffer = node_ptr->get_buffer();
		for (int i = 0; i < (buffer_len - to_be_erased) ; i++) {
			*((char*)(node_buffer) + i) = *((char*)(node_buffer) + to_be_erased + i);
		}
		buffer_len -= to_be_erased;
		erased += to_be_erased;
		node_ptr->set_buffer(node_buffer, buffer_len);
		to_be_erased = 0;

		break;
	}

	return erased;
}

chunked_memory_stream::~chunked_memory_stream()
{
	//printf("In chunked_memory_stream destructor\n");
}

#ifdef CMS_NEVER

void reader(chunked_memory_stream & cms, size_t offset, size_t length)
{
	char string[10];
	int n = 0;
	memset(string,'\0',10);
	n = cms.read(offset, string, length);
	printf("Read %d bytes from offset [%lu] and string is [%s]\n", n, offset, string);

	return ;
}

int main()
{
	char * a = (char*)calloc(1, 2);
	char * b = (char*)calloc(1, 2);
	char * c = (char*)calloc(1, 2);
	char * d = (char*)calloc(1, 2);
	chunked_memory_stream cms;

	memcpy(a, "01", 2);
	cms.push(a, 2);

	memcpy(b, "23", 2);
	cms.push(b, 2);

	memcpy(c, "45", 2);
	cms.push(c, 2);

	memcpy(d, "67", 2);
	cms.push(d, 2);

	reader(cms, 0, 3);
	reader(cms, 1, 1);
	reader(cms, 3, 5);
	reader(cms, 3, 6);
	reader(cms, 8, 6);

	cms.erase(5);
	reader(cms, 0, 8);

	return 0;
}

#endif
