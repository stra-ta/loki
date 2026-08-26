# Per-area test binaries. Each area directory is ownership-isolated: one
# package owns one area directory and never edits another's.
set(LOKI_TEST_AREAS util config transport scheduler reactor faults evidence replay control integration udp)

foreach(area IN LISTS LOKI_TEST_AREAS)
  file(GLOB LOKI_AREA_TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_LIST_DIR}/${area}/*.cpp")
  if(LOKI_AREA_TEST_SOURCES)
    add_executable(loki_test_${area} ${LOKI_AREA_TEST_SOURCES})
    target_link_libraries(loki_test_${area} PRIVATE loki_core loki_warnings Catch2::Catch2WithMain)
    add_test(NAME loki_${area} COMMAND loki_test_${area})
  endif()
endforeach()
