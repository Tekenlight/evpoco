#ifndef LUALIB_H_INCLUDED
#define LUALIB_H_INCLUDED

typedef struct {
    size_t size;
    unsigned char* value;
} binary_data_s1_type, binary_data_p1_type;

typedef struct {
    size_t size;
    unsigned char* value;
} binary_data_s2_type, binary_data_p2_type;

typedef binary_data_s1_type hex_data_s_type;
typedef binary_data_s2_type b64_data_s_type;

#endif // LUALIB_H_INCLUDED
