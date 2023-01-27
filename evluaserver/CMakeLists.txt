set(EXENAME1 "evluaserver")
set(EXENAME2 "evlua")
set(SAMPLE_NAME1 "evluaserver")
set(SAMPLE_NAME2 "evlua")

set(LOCAL_SRCS "")
aux_source_directory(src LOCAL_SRCS)

set(ADD_INCLUDE_DIRECTORIES $ENV{ADD_INCLUDE_DIR})
set(CMAKE_CXX_FLAGS "-Wno-c++17-compat-mangling")

add_executable( ${SAMPLE_NAME1} "src/evluaserver.cpp" "src/evlua_util.cpp" )
add_executable( ${SAMPLE_NAME2} "src/evlua.cpp" "src/evlua_util.cpp" )
target_link_libraries( ${SAMPLE_NAME1} PocoNet evnet PocoUtil PocoFoundation )
target_link_libraries( ${SAMPLE_NAME2} PocoNet evnet PocoUtil PocoFoundation )

find_library(LIBEVGLOBALS NAMES evglobals REQUIRED)
find_library(LIBCORE_UTILS NAMES core_utils REQUIRED)

target_link_libraries( ${SAMPLE_NAME1} "${LIBEVGLOBALS}" )
target_link_libraries( ${SAMPLE_NAME1} "${LIBCORE_UTILS}" )
target_link_libraries( ${SAMPLE_NAME2} "${LIBEVGLOBALS}" )
target_link_libraries( ${SAMPLE_NAME2} "${LIBCORE_UTILS}" )

foreach(dir ${ADD_INCLUDE_DIRECTORIES})
	target_include_directories( "${SAMPLE_NAME1}" PUBLIC "${dir}")
	target_include_directories( "${SAMPLE_NAME2}" PUBLIC "${dir}")
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

if (ENABLE_CRYPTO)
    add_subdirectory(evlcrypto)
endif ()

if (ENABLE_NETSSL)
    add_subdirectory(evlnetssl)
endif ()
