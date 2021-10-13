set(LIBNAME "evpostgres")
set(POCO_LIBNAME "${LIBNAME}")

# Sources
set(SRCS "")
set(SRCS_H "")
set(HDRS_H "")
file(GLOB SRCS_H "src/*.cpp")
POCO_SOURCES_AUTO( SRCS ${SRCS_H})
file(GLOB SRCS_H "src/*.c")
POCO_SOURCES_AUTO( SRCS ${SRCS_H})

# Headers
file(GLOB_RECURSE HDRS_H "include/*.h" )
POCO_HEADERS_AUTO( SRCS ${HDRS_H})

set(ADD_LIBRARY_PATH "$ENV{ADD_LIB}")
set(ADD_INCLUDE_DIRECTORIES $ENV{ADD_INCLUDE_DIR})
# Windows and WindowsCE need additional libraries
if(WIN32)
    if(WINCE)
        set(SYSLIBS ${SYSLIBS} "ws2.lib" "iphlpapi.lib")
    else()    
        set(SYSLIBS ${SYSLIBS} "ws2_32.lib" "iphlpapi.lib")
    endif()    
endif(WIN32)

#message(STATUS "${LIBNAME} " " ${SHARED_LIBRARY_VERSION}" " ${POCO_LIBNAME}" )
if(APPLE)
add_library( "${LIBNAME}" MODULE ${SRCS} ) #This is needed to creare .so file
else(APPLE)
add_library( "${LIBNAME}" ${LIB_MODE} ${SRCS} )
endif(APPLE)

#VERSION AND SOVERSION set -compatibility_version 60.0.0 and -current_version 60.0.0 flags at linker stage.
#These flags are not supported in .so mode MODULE instead of SHARED (for .dylib files on macosx)

if(APPLE)
set_target_properties( "${LIBNAME}"
    PROPERTIES
	LINK_FLAGS "-bind_at_load"
#    VERSION ${SHARED_LIBRARY_VERSION} SOVERSION ${SHARED_LIBRARY_VERSION}
    OUTPUT_NAME ${POCO_LIBNAME}
    DEFINE_SYMBOL evpostgres_EXPORTS
    )
else(APPLE)
set_target_properties( "${LIBNAME}"
    PROPERTIES
    VERSION ${SHARED_LIBRARY_VERSION} SOVERSION ${SHARED_LIBRARY_VERSION}
    OUTPUT_NAME ${POCO_LIBNAME}
    DEFINE_SYMBOL evpostgres_EXPORTS
    )
endif(APPLE)

foreach(lib ${ADD_LIBRARY_PATH})
string(APPEND LINK_TIME_FLAGS " ")
string(APPEND LINK_TIME_FLAGS "-L${lib}")
string(APPEND LINK_TIME_FLAGS " ")
endforeach(lib)
string(STRIP ${LINK_TIME_FLAGS} LINK_TIME_FLAGS)
set(LTF ${LINK_TIME_FLAGS})
#message(STATUS "Here ${LTF}")
#target_link_libraries( "${LIBNAME}" "${LTF}" evnet evdata "-L/opt/local/lib/postgresql13" pq)
#target_link_libraries( "${LIBNAME}" "${LTF}" evnet evdata pq "-L/opt/local/lib/postgresql13" pgtypes)
target_link_libraries( "${LIBNAME}" "${LTF}" evnet evdata pq "-L/opt/local/lib/postgresql13")
target_include_directories( "${LIBNAME}"
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
foreach(dir ${ADD_INCLUDE_DIRECTORIES})
	#include_directories(SYSTEM ${dir})
	string(APPEND INC_DIRS "-I${dir} ")
endforeach(dir)
if (PG_VERSION EQUAL 12)
	message(STATUS PG_VERSION " ${PG_VERSION}")
	#set_target_properties("${LIBNAME}" PROPERTIES APPEND PROPERTY COMPILE_FLAGS "-DPG_VERSION=12")
	add_definitions(-DPG_VERSION=12)
endif(PG_VERSION EQUAL 12)
string(APPEND INC_DIRS " -I/opt/local/include/postgresql13 -I/opt/local/include/postgresql13/server")
set_target_properties("${LIBNAME}" PROPERTIES APPEND PROPERTY COMPILE_FLAGS "${INC_DIRS}")
set(CMAKE_CXX_FLAGS "-Wno-c++17-compat-mangling")


target_compile_definitions("${LIBNAME}" PUBLIC ${LIB_MODE_DEFINITIONS})

POCO_INSTALL("${LIBNAME}")

POCO_GENERATE_PACKAGE("${LIBNAME}")

#if (ENABLE_TESTS)
#add_subdirectory(samples)
#	add_subdirectory(testsuite)
#endif ()
