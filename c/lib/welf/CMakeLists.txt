cmake_minimum_required(VERSION 3.10)
project(welf C)

file(GLOB WELF_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")
add_library(welf STATIC ${WELF_SOURCES})

find_path(LIBUV_INCLUDE_DIR NAMES uv.h)
find_path(ZSTD_INCLUDE_DIR NAMES zstd.h zdict.h zstd_errors.h)
find_path(ZLIB_INCLUDE_DIR NAMES zlib.h)
find_library(LIBUV_LIBRARIES NAMES libuv_a.a libuv.a)
find_library(ZSTD_LIBRARIES NAMES libzstd.a)
find_library(ZLIB_LIBRARIES NAMES libz.a)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

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

add_custom_command(
    TARGET welf POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:welf> ${CMAKE_CURRENT_SOURCE_DIR}/../welf.a
)

add_custom_command(
    TARGET vendor_libelf POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_SOURCE_DIR}/../../vendor/libelf/libelf.a
        ${CMAKE_CURRENT_SOURCE_DIR}/../../vendor/libelf.a
)

target_include_directories(welf PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../vendor/libelf/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../vendor/libelf/src
    ${LIBUV_INCLUDE_DIR}
    ${ZSTD_INCLUDE_DIR}
    ${ZLIB_INCLUDE_DIR}
)

target_link_libraries(welf PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../../vendor/libelf/libelf.a
    ${LIBUV_LIBRARIES}
    ${ZSTD_LIBRARIES}
    ${ZLIB_LIBRARIES}
    OpenSSL::SSL
)

file(GLOB WELF_TESTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.c")
add_executable(welf_tests ${WELF_TESTS})
target_link_libraries(welf_tests PRIVATE welf)

enable_testing()
add_test(NAME welf_tests COMMAND welf_tests)