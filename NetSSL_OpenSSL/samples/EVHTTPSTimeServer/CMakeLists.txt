set(SAMPLE_NAME "EVHTTPSTimeServer")

set(ADD_LIBRARY_PATH "$ENV{ADD_LIB}")

foreach(lib ${ADD_LIBRARY_PATH})
string(APPEND LINK_TIME_FLAGS "-L${lib}")
string(APPEND LINK_TIME_FLAGS " ")
endforeach(lib)
string(STRIP ${LINK_TIME_FLAGS} LINK_TIME_FLAGS)
set(LTF ${LINK_TIME_FLAGS})

set(LOCAL_SRCS "")
aux_source_directory(src LOCAL_SRCS)

message(STATUS "= ${LTF}")
add_executable( ${SAMPLE_NAME} ${LOCAL_SRCS} )
target_link_libraries( ${SAMPLE_NAME} "${LTF}" PocoNetSSL PocoCrypto PocoUtil PocoNet evnet PocoXML PocoFoundation )

foreach(dir ${ADD_INCLUDE_DIRECTORIES})
	target_include_directories( "${SAMPLE_NAME}" PUBLIC "${dir}")
endforeach(dir)
set_target_properties("${SAMPLE_NAME}" PROPERTIES APPEND PROPERTY COMPILE_FLAGS "${INC_DIRS}")
