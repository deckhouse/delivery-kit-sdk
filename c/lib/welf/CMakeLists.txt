cmake_minimum_required(VERSION 3.10)
project(welf C)

file(GLOB WELF_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")
add_library(welf STATIC ${WELF_SOURCES})

find_path(LIBUV_INCLUDE_DIR NAMES uv.h)
find_library(LIBUV_LIBRARIES NAMES uv_a libuv_a uv libuv)
find_library(ZSTD_LIBRARIES NAMES zstd libzstd)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

set(VENDOR_LIBELF_MAKE_FLAGS "")
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(VENDOR_LIBELF_MAKE_FLAGS "DEBUG=1")
endif()

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/../../vendor/libelf/libelf.a
    COMMAND make ${VENDOR_LIBELF_MAKE_FLAGS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../../vendor/libelf
)
add_custom_target(vendor_libelf ALL
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../../vendor/libelf/libelf.a
)
add_dependencies(welf vendor_libelf)

target_include_directories(welf PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../vendor/libelf/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../vendor/libelf/src
    ${LIBUV_INCLUDE_DIR}
)

target_link_libraries(welf PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../../vendor/libelf/libelf.a
    ${LIBUV_LIBRARIES}
    OpenSSL::SSL
    ZLIB::ZLIB
    ${ZSTD_LIBRARIES}
)

file(GLOB WELF_TESTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.c")
add_executable(welf_tests ${WELF_TESTS})
target_link_libraries(welf_tests PRIVATE welf)

enable_testing()
add_test(NAME welf_tests COMMAND welf_tests)

