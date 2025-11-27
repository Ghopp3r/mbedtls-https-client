cmake_minimum_required(VERSION 3.15)
project(curl_alternative LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(ENABLE_VERBOSE_LOGGING "Enable verbose logging for the HTTPS client" OFF)

set(MBEDTLS_ROOT "${CMAKE_CURRENT_LIST_DIR}/third_party/mbedtls")
set(MBEDTLS_INCLUDE "${MBEDTLS_ROOT}/include")
set(MBEDTLS_LIB_DIR "${MBEDTLS_ROOT}/lib")

add_library(mbedtls STATIC IMPORTED)
set_target_properties(
    mbedtls
    PROPERTIES
        IMPORTED_LOCATION "${MBEDTLS_LIB_DIR}/libmbedtls.a"
        INTERFACE_INCLUDE_DIRECTORIES "${MBEDTLS_INCLUDE}"
)

add_library(mbedx509 STATIC IMPORTED)
set_target_properties(
    mbedx509
    PROPERTIES
        IMPORTED_LOCATION "${MBEDTLS_LIB_DIR}/libmbedx509.a"
        INTERFACE_INCLUDE_DIRECTORIES "${MBEDTLS_INCLUDE}"
)

add_library(mbedcrypto STATIC IMPORTED)
set_target_properties(
    mbedcrypto
    PROPERTIES
        IMPORTED_LOCATION "${MBEDTLS_LIB_DIR}/libmbedcrypto.a"
        INTERFACE_INCLUDE_DIRECTORIES "${MBEDTLS_INCLUDE}"
)

add_executable(curl_alt
    src/Main.cpp
    src/HttpsClient.cpp
)

target_compile_options(
    curl_alt
    PRIVATE
        -fvisibility=hidden
        -fvisibility-inlines-hidden
        -fdata-sections
        -ffunction-sections
)

target_include_directories(
    curl_alt
    PRIVATE
        "${CMAKE_CURRENT_LIST_DIR}/src"
        "${MBEDTLS_INCLUDE}"
)

target_link_libraries(
    curl_alt
    PRIVATE
        mbedtls
        mbedx509
        mbedcrypto
)

target_link_options(
    curl_alt
    PRIVATE
        -Wl,--gc-sections
        -Wl,-s
)

if (ANDROID)
    find_library(ANDROID_LOG_LIB log)
    if (ANDROID_LOG_LIB)
        target_link_libraries(curl_alt PRIVATE "${ANDROID_LOG_LIB}")
    endif()
endif()

if (ENABLE_VERBOSE_LOGGING)
    target_compile_definitions(curl_alt PRIVATE ENABLE_VERBOSE_LOGGING=1)
endif()
