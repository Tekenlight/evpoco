set(SAMPLE_NAME "EVHTTPOrchServer")

set(LOCAL_SRCS "")
aux_source_directory(src LOCAL_SRCS)

set(CMAKE_CXX_FLAGS "-Wno-c++17-compat-mangling")

add_executable( ${SAMPLE_NAME} ${LOCAL_SRCS} )
target_link_libraries( ${SAMPLE_NAME} PocoNet evnet PocoUtil PocoJSON PocoXML PocoFoundation )

foreach(dir ${ADD_INCLUDE_DIRECTORIES})
	target_include_directories( "${SAMPLE_NAME}" PUBLIC "${dir}")
endforeach(dir)
#set_target_properties("${SAMPLE_NAME}" PROPERTIES APPEND PROPERTY COMPILE_FLAGS "${INC_DIRS}")
