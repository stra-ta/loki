file(GLOB LOKI_CLI_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_LIST_DIR}/*.cpp")
add_executable(loki ${LOKI_CLI_SOURCES})
target_link_libraries(loki PRIVATE loki_core loki_warnings)
