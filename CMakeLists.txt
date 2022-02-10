cmake_minimum_required(VERSION 3.10)
project(rgcp VERSION 1.0.1 DESCRIPTION "RGCP networking middleware")
include(GNUInstallDirs)

set(TARGET_NAME rgcp_middleware)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

set(PROJECT_SOURCE_DIR ${CMAKE_SOURCE_DIR}/src)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)

add_executable(${TARGET_NAME}
    src/details/api_packet.c
    src/details/rgcp_group.c
    src/client.c
    src/middleware.c
)

find_package(Threads)

target_compile_options(${TARGET_NAME} PRIVATE -Wall -Wextra -Werror -pedantic -g)

target_link_libraries(${TARGET_NAME} ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(${TARGET_NAME} dl pthread rgcp)

set_target_properties(${TARGET_NAME} PROPERTIES
    VERSION ${PROJECT_VERSION}
)

target_include_directories(${TARGET_NAME} PRIVATE src)
target_include_directories(${TARGET_NAME} PRIVATE include)

install(
    TARGETS ${TARGET_NAME}
    RUNTIME
)
