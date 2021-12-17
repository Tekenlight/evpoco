set(EXENAME1 "evluaserver")
set(EXENAME2 "evlua")
set(SAMPLE_NAME1 "evluaserver")
set(SAMPLE_NAME2 "evlua")

set(LOCAL_SRCS "")
aux_source_directory(src LOCAL_SRCS)

set(ADD_LIBRARY_PATH "$ENV{ADD_LIB}")
set(ADD_INCLUDE_DIRECTORIES $ENV{ADD_INCLUDE_DIR})
set(CMAKE_CXX_FLAGS "-Wno-c++17-compat-mangling")

add_executable( ${SAMPLE_NAME1} "src/evluaserver.cpp" "src/evlua_util.cpp" )
add_executable( ${SAMPLE_NAME2} "src/evlua.cpp" "src/evlua_util.cpp" )
target_link_libraries( ${SAMPLE_NAME1} PocoNet evnet PocoUtil PocoFoundation evglobals core_utils )
target_link_libraries( ${SAMPLE_NAME2} PocoNet evnet PocoUtil PocoFoundation evglobals core_utils )

foreach(dir ${ADD_INCLUDE_DIRECTORIES})
	string(APPEND INC_DIRS " -I${dir} ")
endforeach(dir)
set_target_properties("${SAMPLE_NAME1}" PROPERTIES APPEND PROPERTY COMPILE_FLAGS "${INC_DIRS}")
set_target_properties("${SAMPLE_NAME2}" PROPERTIES APPEND PROPERTY COMPILE_FLAGS "${INC_DIRS}")


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
