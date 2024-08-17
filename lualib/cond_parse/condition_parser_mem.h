#ifndef CONDITION_PARSER_MEM_H_INCLUDED
#define CONDITION_PARSER_MEM_H_INCLUDED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct _cond_mem_node_s {
    struct _cond_mem_node_s * prev;
    struct _cond_mem_node_s * next;
    char * buf;
    size_t s;
};

typedef struct _cond_mem_node_s cond_mem_node_s;
typedef struct _cond_mem_node_s* cond_mem_node_t;

struct _parsed_output_s {
    char *buffer;
    size_t len;
    cond_mem_node_t buflist;
    int n_const;
    int n_var;
};
typedef struct _parsed_output_s parsed_output_s;
typedef struct _parsed_output_s* parsed_output_t;


void store_output(parsed_output_t output, char *result);
cond_mem_node_t create_output_buf(parsed_output_t output, char * token1, char * token2, char* token3);
void destroy_output(parsed_output_t output);
void reset_output(parsed_output_t output);
parsed_output_t new_parsed_output();

cond_mem_node_t alloc_dupbuf(parsed_output_t output, char* inp);
void free_dup_buf(parsed_output_t output, cond_mem_node_t np);
void free_dup_bufs(parsed_output_t output, cond_mem_node_t np1, cond_mem_node_t np2, cond_mem_node_t np3);
cond_mem_node_t alloc_const(parsed_output_t output, char * inp);
cond_mem_node_t alloc_var(parsed_output_t output, char * inp);
#endif /* CONDITION_PARSER_MEM_H_INCLUDED */
