set(LIBNAME "evdata")
set(POCO_LIBNAME "${LIBNAME}")

# Sources
file(GLOB SRCS_G "src/*.cpp")
POCO_SOURCES_AUTO( SRCS ${SRCS_G})
file(GLOB SRCS_G "src/*.c")
POCO_SOURCES_AUTO( SRCS ${SRCS_G})

# Headers
file(GLOB_RECURSE HDRS_G "include/*.h" )
POCO_HEADERS_AUTO( SRCS ${HDRS_G})

set(ADD_LIBRARY_PATH "$ENV{ADD_LIB}")
set(ADD_INCLUDE_DIRECTORIES $ENV{ADD_INCLUDE_DIR})
set(CMAKE_CXX_FLAGS "-Wno-c++17-compat-mangling")

# Windows and WindowsCE need additional libraries
if(WIN32)
    if(WINCE)
        set(SYSLIBS ${SYSLIBS} "ws2.lib" "iphlpapi.lib")
    else()    
        set(SYSLIBS ${SYSLIBS} "ws2_32.lib" "iphlpapi.lib")
    endif()    
endif(WIN32)

add_library( "${LIBNAME}" ${LIB_MODE} ${SRCS} )
#add_library( "${LIBNAME}" STATIC ${SRCS} )
#add_library( "${POCO_LIBNAME}" ALIAS "${LIBNAME}")

if(APPLE)
set_target_properties( "${LIBNAME}"
    PROPERTIES
	LINK_FLAGS "-bind_at_load"
    VERSION ${SHARED_LIBRARY_VERSION} SOVERSION ${SHARED_LIBRARY_VERSION}
    OUTPUT_NAME ${POCO_LIBNAME}
    DEFINE_SYMBOL evdata_EXPORTS
    )
else(APPLE)
set_target_properties( "${LIBNAME}"
    PROPERTIES
    VERSION ${SHARED_LIBRARY_VERSION} SOVERSION ${SHARED_LIBRARY_VERSION}
    OUTPUT_NAME ${POCO_LIBNAME}
    DEFINE_SYMBOL evdata_EXPORTS
    )
endif(APPLE)

foreach(lib ${ADD_LIBRARY_PATH})
string(APPEND LINK_TIME_FLAGS "-L${lib}")
string(APPEND LINK_TIME_FLAGS " ")
endforeach(lib)
string(STRIP ${LINK_TIME_FLAGS} LINK_TIME_FLAGS)
set(LTF ${LINK_TIME_FLAGS})
#message(STATUS "Here ${LTF}")
target_link_libraries( "${LIBNAME}" "${LTF}" evnet )
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
#string(STRIP ${INC_DIRS} INC_DIRS)
set_target_properties("${LIBNAME}" PROPERTIES APPEND PROPERTY COMPILE_FLAGS "${INC_DIRS}")

target_compile_definitions("${LIBNAME}" PUBLIC ${LIB_MODE_DEFINITIONS})

POCO_INSTALL("${LIBNAME}")

POCO_GENERATE_PACKAGE("${LIBNAME}")

if (ENABLE_SQLITE)
    add_subdirectory(evsqlite)
#	add_subdirectory(testsuite)
endif ()
