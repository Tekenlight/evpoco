set(LIBNAME "lualib")
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
set(CMAKE_CXX_FLAGS "-Wno-c++17-compat-mangling")

# Windows and WindowsCE need additional libraries
if(WIN32)
    if(WINCE)
        set(SYSLIBS ${SYSLIBS} "ws2.lib" "iphlpapi.lib")
    else()    
        set(SYSLIBS ${SYSLIBS} "ws2_32.lib" "iphlpapi.lib")
    endif()    
endif(WIN32)

if (APPLE)
	add_library( "${LIBNAME}" ${LIB_MODE} ${SRCS} ) #This is needed to creare .so file
else(APPLE)
	add_library( "${LIBNAME}" ${LIB_MODE} ${SRCS} )
endif(APPLE)

if(APPLE)
set_target_properties( "${LIBNAME}"
    PROPERTIES
#	LINK_FLAGS "-bind_at_load"
	LINK_FLAGS "-fpic -Wl,-all_load"
    VERSION ${SHARED_LIBRARY_VERSION} SOVERSION ${SHARED_LIBRARY_VERSION}
#   VERSION ${SHARED_LIBRARY_VERSION} SOVERSION ${SHARED_LIBRARY_VERSION}
    OUTPUT_NAME ${POCO_LIBNAME}
    DEFINE_SYMBOL lualib_EXPORTS
    )
else(APPLE)

set_target_properties( "${LIBNAME}"
    PROPERTIES
	LINK_FLAGS "-fpic"
    VERSION ${SHARED_LIBRARY_VERSION} SOVERSION ${SHARED_LIBRARY_VERSION}
    OUTPUT_NAME ${POCO_LIBNAME}
    DEFINE_SYMBOL lualib_EXPORTS
    )
endif(APPLE)

function(lualib_check validator_result_var item)
	#if(NOT item MATCHES ...)
	#	set(${validator_result_var} FALSE PARENT_SCOPE)
	#endif()
	message(STATUS "IN VALIDATOR")
	message(STATUS "${item}")
	message(STATUS "IN VALIDATOR")
	message(STATUS "${validator_result_var}")
	message(STATUS "IN VALIDATOR")

endfunction()

find_library(LIBLUA NAMES lua NO_DEFAULT_PATH PATHS "${CMAKE_INSTALL_PREFIX}/lib" NO_CACHE REQUIRED )
message(STATUS "FOUND LUALIB ${LIBLUA}")
if(APPLE)
	target_link_libraries( "${LIBNAME}" ${LIBLUA} )
else(APPLE)
	target_link_libraries( "${LIBNAME}" "-Wl,--whole-archive,--no-whole-archive" )
	target_link_libraries( "${LIBNAME}" ${LIBLUA} )
endif(APPLE)

target_include_directories( "${LIBNAME}"
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_INSTALL_PREFIX}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
foreach(dir ${ADD_INCLUDE_DIRECTORIES})
	target_include_directories( "${LIBNAME}" PUBLIC "${dir}")
endforeach(dir)
target_compile_definitions("${LIBNAME}" PUBLIC ${LIB_MODE_DEFINITIONS})

POCO_INSTALL("${LIBNAME}")
POCO_GENERATE_PACKAGE("${LIBNAME}")
