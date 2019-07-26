#ifndef MEMORY_BUFFER_LIST_H_INCLUDED
#define MEMORY_BUFFER_LIST_H_INCLUDED

#include <sys/types.h>
#include <stdatomic.h>
#include <pthread.h>
#include <ev_include.h>



class memory_buffer_list {
// Singly Linked List - Concurrent for 2 threads.
// Designed for concurrent operations by 2 threads.
// 1st Thread trying add record at the tail
// 2nd thread trying to either
// (a) Read data from nodes (anywhere in the list, inclusive of tail)
// (b) Pop nodes at head (inclusive of tail, if head == tail)
//
// Operations
// 	(a) -> add node at tail
// 	(b) -> read data from nodes (anywhere)
// 	(c) -> pop node at head
//
// Contention points
// 	(1) ->	While new node is being added at the tail by 1 thread
// 			Another thread tries to read contents of the tail
// 			->	The reader may conclude that there is no more data,
// 				while new data addition is just round the corner.
// 				This situation is OK, as the reader thread will
// 				get another chance to read remaining data in another
// 				event, caused by writer thread.
// 	(2) ->	Tail may be popped while a new node is being added (ahead
// 			of tail)
// 			->	This is a contention and here is where the algorithm will
// 				become wait-free for additions and obstruction-free for popping
// 				The thread that is popping will fail due to marking of pointers
// 				and retry popping once again. It will succeed in the next round.
//
// 	Since only one of the two threads can either pop or read, there are no contention
// 	points in get_next

public:
	class node {
		public:
			node();

			void set_buffer(void * buffer, size_t size);
			void set_next(node *);
			size_t get_buffer_len();
			void * get_buffer();
			node * get_next();

			~node();
		private:
			atomic_uintptr_t _next;
			void * _buffer;
			size_t _size;
	};
	memory_buffer_list();

	node * get_head();

	node * get_next(node *);

	node * get_tail();

	void add_node(void *, size_t);
	// Adds buffer data as a new node in the buffer list.
	// Data will not be copied to new memory etc.
	// The caller is expected to allocate memory (chunky enough)
	// The caller is also expected to not free the memory.
	// It will be freed when the node gets popped out.
	//
	
	node * pop_head();

	~memory_buffer_list();

private:
	atomic_uintptr_t _head;
	atomic_uintptr_t _tail;
};

#endif

