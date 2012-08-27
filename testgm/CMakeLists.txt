INCLUDE( ${CMAKE_MODULE_PATH}/FindGMP.cmake OPTIONAL)
include_directories(${LIBGM_SOURCE_DIR}/libgm ${GMP_INCLUDE_DIR})

link_directories(${LIBGM_BINARY_DIR}/libgm)

add_executable (testgm testgm.c)

target_link_libraries(testgm libgm ${GMP_LIBRARIES})
