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
#add_library( "${LIBNAME}" STATIC ${SRCS} )
#add_library( "${POCO_LIBNAME}" ALIAS "${LIBNAME}")

if(APPLE)
set_target_properties( "${LIBNAME}"
    PROPERTIES
	LINK_FLAGS "-bind_at_load"
#    VERSION ${SHARED_LIBRARY_VERSION} SOVERSION ${SHARED_LIBRARY_VERSION}
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

target_link_libraries( "${LIBNAME}" evnet evluautil )
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
add_subdirectory(evclient)
add_subdirectory(evpoolrepos)

if (ENABLE_EVSQLITE)
    add_subdirectory(evsqlite)
#	add_subdirectory(testsuite)
endif ()
if (ENABLE_EVPOSTGRES)
    add_subdirectory(evpostgres)
#	add_subdirectory(testsuite)
endif ()
if (ENABLE_EVREDIS)
    add_subdirectory(evredis)
#	add_subdirectory(testsuite)
endif ()
