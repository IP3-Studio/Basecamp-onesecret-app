cmake_minimum_required(VERSION 3.14)
project(OnesecretUiPlugin LANGUAGES CXX)

if(DEFINED ENV{LOGOS_MODULE_BUILDER_ROOT})
    include($ENV{LOGOS_MODULE_BUILDER_ROOT}/cmake/LogosModule.cmake)
else()
    message(FATAL_ERROR "LogosModule.cmake not found. Set LOGOS_MODULE_BUILDER_ROOT.")
endif()

# Derive the module name from metadata.json — single source of truth.
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/metadata.json" METADATA_JSON)
string(JSON MODULE_NAME GET ${METADATA_JSON} name)

# Universal UI module: the .rep plus the *Backend class are hand-written; the
# generated *Plugin glue is compiled automatically. libcrypto reaches the plugin
# through logos-protocol's exported target (every Basecamp plugin already ships
# libcrypto.3); the explicit link below only makes the dependency visible.
logos_module(
    NAME ${MODULE_NAME}
    REP_FILE src/onesecret_ui.rep
    SOURCES
        src/onesecret_ui_backend.h
        src/onesecret_ui_backend.cpp
        src/crypto.h
        src/crypto.cpp
        src/names.h
        src/names.cpp
        src/keystore.h
        src/keystore.cpp
    INCLUDE_DIRS
        src
)

# The at-rest key lives in the login Keychain on macOS (src/keystore.cpp).
if(APPLE)
    target_link_libraries(${MODULE_NAME}_module_plugin PRIVATE "-framework Security" "-framework CoreFoundation")
endif()

# DNS TXT lookups for reader-name verification (QDnsLookup).
find_package(Qt6 REQUIRED COMPONENTS Network)
target_link_libraries(${MODULE_NAME}_module_plugin PRIVATE Qt6::Network)

if(TARGET OpenSSL::Crypto)
    target_link_libraries(${MODULE_NAME}_module_plugin PRIVATE OpenSSL::Crypto)
else()
    find_package(OpenSSL REQUIRED)
    target_link_libraries(${MODULE_NAME}_module_plugin PRIVATE OpenSSL::Crypto)
endif()
