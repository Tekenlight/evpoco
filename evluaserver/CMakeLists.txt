set(EXENAME1 "evluaserver")
set(EXENAME2 "evlua")
set(SAMPLE_NAME2 "evlua")
set(LIBNAME "evluautil")
set(POCO_LIBNAME "${LIBNAME}")

set(LOCAL_SRCS "")
aux_source_directory(src LOCAL_SRCS)

set(CMAKE_CXX_FLAGS "-Wno-c++17-compat-mangling")

add_library( "${LIBNAME}" ${LIB_MODE} "src/evlua_util.cpp" )
set_target_properties( "${LIBNAME}"
    PROPERTIES
    VERSION ${SHARED_LIBRARY_VERSION} SOVERSION ${SHARED_LIBRARY_VERSION}
    OUTPUT_NAME ${POCO_LIBNAME}
    DEFINE_SYMBOL evluautil_EXPORTS
    )

add_executable( ${EXENAME1} "src/evluaserver.cpp" )
add_executable( ${EXENAME2} "src/evlua.cpp" )
target_link_libraries( ${EXENAME1} ${LIBNAME} PocoNet evnet PocoUtil PocoFoundation )
target_link_libraries( ${EXENAME2} ${LIBNAME} PocoNet evnet PocoUtil PocoFoundation )

find_library(LIBEVGLOBALS NAMES evglobals REQUIRED)
find_library(LIBCORE_UTILS NAMES core_utils REQUIRED)
find_library(LIBEVSYNC NAMES evsync REQUIRED)

target_link_libraries( ${LIBNAME} "${LIBEVGLOBALS}" )
target_link_libraries( ${LIBNAME} "${LIBCORE_UTILS}" )
target_link_libraries( ${LIBNAME} "${LIBEVSYNC}" )

foreach(dir ${ADD_INCLUDE_DIRECTORIES})
	target_include_directories( "${EXENAME1}" PUBLIC "${dir}")
	target_include_directories( "${EXENAME2}" PUBLIC "${dir}")
	target_include_directories( "${LIBNAME}" PUBLIC "${dir}")
endforeach(dir)

set_target_properties( "${EXENAME1}"
    PROPERTIES
    OUTPUT_NAME evluaserver
    )

set_target_properties( "${EXENAME2}"
    PROPERTIES
    OUTPUT_NAME evlua
    )

install(
	TARGETS "${EXENAME1}" EXPORT "${EXENAME1}Targets"
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
    )

install(
	TARGETS "${EXENAME2}" EXPORT "${EXENAME2}Targets"
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
    )

POCO_INSTALL("${LIBNAME}")
POCO_GENERATE_PACKAGE("${LIBNAME}")

if (ENABLE_CRYPTO)
    add_subdirectory(evlcrypto)
endif ()

if (ENABLE_NETSSL)
    add_subdirectory(evlnetssl)
endif ()
