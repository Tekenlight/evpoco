set(SAMPLE_NAME "EVHTTPFormServer")

set(LOCAL_SRCS "")
aux_source_directory(src LOCAL_SRCS)

set(ADD_LIBRARY_PATH "$ENV{ADD_LIB}")
set(ADD_INCLUDE_DIRECTORIES $ENV{ADD_INCLUDE_DIR})
set(CMAKE_CXX_FLAGS "-Wno-c++17-compat-mangling")

add_executable( ${SAMPLE_NAME} ${LOCAL_SRCS} )
target_link_libraries( ${SAMPLE_NAME} PocoNet PocoEVNet PocoUtil PocoJSON PocoXML PocoFoundation )

foreach(dir ${ADD_INCLUDE_DIRECTORIES})
	string(APPEND INC_DIRS " -I${dir} ")
endforeach(dir)
set_target_properties("${SAMPLE_NAME}" PROPERTIES APPEND PROPERTY COMPILE_FLAGS "${INC_DIRS}")
