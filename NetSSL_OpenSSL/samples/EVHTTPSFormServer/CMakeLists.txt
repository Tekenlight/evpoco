set(SAMPLE_NAME "EVHTTPSFormServer")

include_directories($ENV{LIBEV_INCLUDE_DIR})

set(LOCAL_SRCS "")
aux_source_directory(src LOCAL_SRCS)

add_executable( ${SAMPLE_NAME} ${LOCAL_SRCS} )
target_link_libraries( ${SAMPLE_NAME} PocoNetSSL PocoCrypto PocoNet PocoUtil PocoJSON PocoXML PocoFoundation )
