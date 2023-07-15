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

add_library( "${LIBNAME}" ${LIB_MODE} ${SRCS} )

set_target_properties( "${LIBNAME}"
    PROPERTIES
    VERSION ${SHARED_LIBRARY_VERSION} SOVERSION ${SHARED_LIBRARY_VERSION}
    OUTPUT_NAME ${POCO_LIBNAME}
    DEFINE_SYMBOL evpostgres_EXPORTS
    )

set(CMAKE_CXX_FLAGS "-Wno-c++17-compat-mangling")
target_compile_definitions("${LIBNAME}" PUBLIC ${LIB_MODE_DEFINITIONS})

target_include_directories( "${LIBNAME}"
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# The additional includes are to take hiredis into consideration
foreach(dir ${ADD_INCLUDE_DIRECTORIES})
	target_include_directories( "${LIBNAME}" PUBLIC "${dir}")
endforeach(dir)

if (DEFINED PG_BUILD_PATH)
	message(STATUS "PG_BUILD_PATH  ......")
	message(STATUS "PG_BUILD_PATH  ${PG_BUILD_PATH}")

	target_include_directories( "${LIBNAME}" PUBLIC "${PG_BUILD_PATH}/usr/local/pgsql/include")

	target_compile_definitions("${LIBNAME}" PRIVATE -DBUILT_PG=1 )

	find_library(LIBPQ NAMES "libpq.a" NO_DEFAULT_PATH PATHS "${PG_BUILD_PATH}/usr/local/pgsql/lib" REQUIRED)
	find_library(LIBPQ_1 NAMES "libpgcommon.a" NO_DEFAULT_PATH PATHS "${PG_BUILD_PATH}/usr/local/pgsql/lib" REQUIRED)
	find_library(LIBPQ_2 NAMES "libpgcommon_shlib.a" NO_DEFAULT_PATH PATHS "${PG_BUILD_PATH}/usr/local/pgsql/lib" REQUIRED)
	find_library(LIBPQ_3 NAMES "libpgport_shlib.a" NO_DEFAULT_PATH PATHS "${PG_BUILD_PATH}/usr/local/pgsql/lib" REQUIRED)

	target_link_libraries( "${LIBNAME}" evdata evnet "${LIBPQ}" "${LIBPQ_1}" "${LIBPQ_2}" "${LIBPQ_3}" NetSSL Crypto )

elseif (DEFINED PG_VERSION) 
	if (APPLE)
		if (DEFINED TARGET_OS_OSX_HOMEBREW)
			target_include_directories( "${LIBNAME}" PUBLIC "/opt/homebrew/include/")
			target_compile_definitions("${LIBNAME}" PRIVATE -DTARGET_OS_OSX_HOMEBREW=1)
		else (DEFINED TARGET_OS_OSX_HOMEBREW)
			target_include_directories( "${LIBNAME}" PUBLIC "/opt/local/include/")
		endif ()
	endif ()

	message(STATUS PG_VERSION " ${PG_VERSION}")

	find_library(LIBPQ NAMES pq REQUIRED PATH_SUFFIXES "postgresql${PG_VERSION}" "postgresql/${PG_VERSION}" "postgresql@${PG_VERSION}" )
	target_compile_definitions("${LIBNAME}" PRIVATE -DPG_VERSION=${PG_VERSION})

	target_link_libraries( "${LIBNAME}" evdata evnet "${LIBPQ}" NetSSL Crypto )

else(DEFINED PG_VERSION)
	message(FATAL_ERROR "VARIABLE PG_BUILD_PATH OR PG_VERSION NOT DEFINED")
endif(DEFINED PG_BUILD_PATH)

POCO_INSTALL("${LIBNAME}")
POCO_GENERATE_PACKAGE("${LIBNAME}")

#if (ENABLE_TESTS)
#add_subdirectory(samples)
#	add_subdirectory(testsuite)
#endif ()
