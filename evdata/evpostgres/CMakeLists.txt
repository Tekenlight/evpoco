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

# Windows and WindowsCE need additional libraries
if(WIN32)
    if(WINCE)
        set(SYSLIBS ${SYSLIBS} "ws2.lib" "iphlpapi.lib")
    else()    
        set(SYSLIBS ${SYSLIBS} "ws2_32.lib" "iphlpapi.lib")
    endif()    
endif(WIN32)

if(APPLE)
	add_library( "${LIBNAME}" MODULE ${SRCS} ) #This is needed to creare .so file
else(APPLE)
	add_library( "${LIBNAME}" ${LIB_MODE} ${SRCS} )
endif(APPLE)

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

target_include_directories( "${LIBNAME}"
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if (PG_VERSION EQUAL 12)
	message(STATUS PG_VERSION " ${PG_VERSION}")
	add_definitions(-DPG_VERSION=12)
	find_library(LIBPQ NAMES pq REQUIRED PATH_SUFFIXES "postgresql12" "postgresql/12" )
elseif(PG_VERSION EQUAL 13)
	message(STATUS PG_VERSION " ${PG_VERSION}")
	add_definitions(-DPG_VERSION=13)
	find_library(LIBPQ NAMES pq REQUIRED PATH_SUFFIXES "postgresql13" "postgresql/13" )
elseif (PG_VERSION EQUAL 14)
	message(STATUS PG_VERSION " ${PG_VERSION}")
	add_definitions(-DPG_VERSION=14)
	find_library(LIBPQ NAMES pq REQUIRED PATH_SUFFIXES "postgresql14" "postgresql/14" )
elseif(PG_VERSION EQUAL 15)
	message(STATUS PG_VERSION " ${PG_VERSION}")
	add_definitions(-DPG_VERSION=15)
	find_library(LIBPQ NAMES pq REQUIRED PATH_SUFFIXES "postgresql14" "postgresql/14" )
endif()

# The additional includes are to take hiredis into consideration
foreach(dir ${ADD_INCLUDE_DIRECTORIES})
	target_include_directories( "${LIBNAME}" PUBLIC "${dir}")
endforeach(dir)
target_link_libraries( "${LIBNAME}" evdata evnet "${LIBPQ}" )

if (APPLE)
	target_include_directories( "${LIBNAME}" PUBLIC "/opt/local/include/")
endif ()

set(CMAKE_CXX_FLAGS "-Wno-c++17-compat-mangling")
target_compile_definitions("${LIBNAME}" PUBLIC ${LIB_MODE_DEFINITIONS})

POCO_INSTALL("${LIBNAME}")
POCO_GENERATE_PACKAGE("${LIBNAME}")

#if (ENABLE_TESTS)
#add_subdirectory(samples)
#	add_subdirectory(testsuite)
#endif ()
