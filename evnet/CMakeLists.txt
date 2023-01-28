set(LIBNAME "evnet")
set(POCO_LIBNAME "${LIBNAME}")

# Sources
file(GLOB SRCS_G "src/*.cpp" "src/*.c")
POCO_SOURCES_AUTO( SRCS ${SRCS_G})

# Headers
file(GLOB_RECURSE HDRS_G "include/*.h" )
POCO_HEADERS_AUTO( SRCS ${HDRS_G})

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
#add_library( "${POCO_LIBNAME}" ALIAS "${LIBNAME}")
set_target_properties( "${LIBNAME}"
    PROPERTIES
    VERSION ${SHARED_LIBRARY_VERSION} SOVERSION ${SHARED_LIBRARY_VERSION}
    OUTPUT_NAME ${POCO_LIBNAME}
    DEFINE_SYMBOL evnet_EXPORTS
    )

target_link_libraries( "${LIBNAME}" Foundation Net Util lualib)
find_library(LIBEV NAMES ev REQUIRED PATH_SUFFIXES "evlua")
find_library(LIBEVDS NAMES evds REQUIRED)
find_library(LIBEVSYNC NAMES evsync REQUIRED)
find_library(LIBEVIO NAMES evio REQUIRED)
find_library(LIBEVTHRPOOL NAMES evthrpool REQUIRED)
find_library(LIBHTTP_PARSER NAMES http_parser REQUIRED PATH_SUFFIXES "evlua")
find_library(LIBHIREDIS NAMES hiredis REQUIRED PATH_SUFFIXES "evlua")
target_link_libraries( "${LIBNAME}" ${LIBEV} ${LIBEVDS} ${LIBEVSYNC} ${LIBEVIO} ${LIBEVTHRPOOL} ${LIBHTTP_PARSER} ${LIBHIREDIS} )

target_include_directories( "${LIBNAME}"
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
foreach(dir ${ADD_INCLUDE_DIRECTORIES})
	target_include_directories( "${LIBNAME}" PUBLIC "${dir}")
endforeach(dir)

target_compile_definitions("${LIBNAME}" PUBLIC ${LIB_MODE_DEFINITIONS})

POCO_INSTALL("${LIBNAME}")
POCO_GENERATE_PACKAGE("${LIBNAME}")

if (ENABLE_TESTS)
    add_subdirectory(samples)
#	add_subdirectory(testsuite)
endif ()
