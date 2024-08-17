#include "condition_parser_mem.h"

/*
static int a = 0;
static int f = 0;
*/

void store_output(parsed_output_t output, char *result)
{
    //printf("%s:%d allocating [%d]th time\n", __FILE__, __LINE__,  ++a);
    output->len += strlen(result);
    output->buffer = malloc(output->len + 1);
    strcpy(output->buffer, result);
}

void reset_output(parsed_output_t output)
{
    if (output->buffer)
        free(output->buffer);

    if (output->buflist) {
        cond_mem_node_t t_np = NULL;
        cond_mem_node_t np = output->buflist;
        output->buflist = NULL;
        while (np) {
            //printf("%s:%d Freeing [%d]th time\n", __FILE__, __LINE__,  ++f);
            free(np->buf);
            t_np = np->next;
            //printf("%s:%d Freeing [%d]th time\n", __FILE__, __LINE__,  ++f);
            free(np);
            np = t_np;
            t_np = NULL;
        }   
    }

    memset(output, 0, sizeof(parsed_output_s));

    return;
}

void destroy_output(parsed_output_t output)
{
    if (output->buffer)
        free(output->buffer);

    if (output->buflist) {
        cond_mem_node_t t_np = NULL;
        cond_mem_node_t np = output->buflist;
        output->buflist = NULL;
        while (np) {
            //printf("%s:%d Freeing [%d]th time\n", __FILE__, __LINE__,  ++f);
            free(np->buf);
            t_np = np->next;
            //printf("%s:%d Freeing [%d]th time\n", __FILE__, __LINE__,  ++f);
            free(np);
            np = t_np;
            t_np = NULL;
        }   
    }

    //printf("%s:%d Freeing [%d]th time\n", __FILE__, __LINE__,  ++f);
    free(output);
}

parsed_output_t new_parsed_output()
{
    //printf("%s:%d allocating [%d]th time\n", __FILE__, __LINE__,  ++a);
    parsed_output_t output = malloc(sizeof(parsed_output_s));
    memset(output, 0, sizeof(parsed_output_s));

    return output;
}

static void add_node(parsed_output_t output, cond_mem_node_t np)
{
    np->next = output->buflist;
    if (output->buflist) output->buflist->prev = np;
    output->buflist = np;

    return;
}

cond_mem_node_t alloc_dupbuf(parsed_output_t output, char* inp)
{
    //printf("%s:%d allocating %s [%d]th time\n", __FILE__, __LINE__,  inp, ++a);
    cond_mem_node_t np = malloc(sizeof(cond_mem_node_s));
    memset(np, 0, sizeof(cond_mem_node_s));

    add_node(output, np);
    
    np->s = strlen(inp);
    np->buf = strdup(inp);
    //printf("%s:%d allocating node for %s [%d]th time\n", __FILE__, __LINE__,  inp, ++a);

    return np;
}

void free_dup_buf(parsed_output_t output, cond_mem_node_t np)
{
    if (!np) return;
    if (output->buflist == np) {
        output->buflist = np->next;
    }
    else if (np->next != NULL) {
        np->prev->next = np->next;
        np->next->prev = np->prev;
    }
    else {
        np->prev->next = np->next;
    }
    //printf("%s:%d Freeing [%d]th time\n", __FILE__, __LINE__,  ++f);
    free(np->buf);
    //printf("%s:%d Freeing [%d]th time\n", __FILE__, __LINE__,  ++f);
    free(np);
}

void free_dup_bufs(parsed_output_t output, cond_mem_node_t np1, cond_mem_node_t np2, cond_mem_node_t np3)
{
    free_dup_buf(output, np1);
    free_dup_buf(output, np2);
    free_dup_buf(output, np3);
}

static cond_mem_node_t alloc_buf(parsed_output_t output, size_t len)
{
    //printf("%s:%d allocating [%d]th time\n", __FILE__, __LINE__,  ++a);
    cond_mem_node_t np = malloc(sizeof(cond_mem_node_s));
    memset(np, 0, sizeof(cond_mem_node_s));

    add_node(output, np);

    np->s = len;
    np->buf = malloc(len);
    memset(np->buf, 0, len);
    //printf("%s:%d allocating [%d]th time\n", __FILE__, __LINE__,  ++a);

    return np;
}

cond_mem_node_t create_output_buf(parsed_output_t output, char * token1, char * token2, char* token3)
{
    size_t len = 3; // Two additional spaces and one sentinel char
    cond_mem_node_t np = NULL;

    len += strlen(token1);
    if (token2) len += strlen(token2);
    if (token3) len += strlen(token3);

    np = alloc_buf(output, len);
    strcat(np->buf, token1);
    if (token2) {
        strcat(np->buf, " ");
        strcat(np->buf, token2);
    }
    if (token3) {
        strcat(np->buf, " ");
        strcat(np->buf, token3);
    }

    return np;
}

cond_mem_node_t alloc_const(parsed_output_t output, char * inp)
{
    if (output->n_const > 1024) {
        return NULL;
    }
    cond_mem_node_t np = alloc_dupbuf(output, inp);
    output->n_const++;
    return np;
}

cond_mem_node_t alloc_var(parsed_output_t output, char * inp)
{
    if (output->n_var > 1024) {
        return NULL;
    }
    cond_mem_node_t np = alloc_dupbuf(output, inp);
    output->n_var++;
    return np;
}

