cmake_minimum_required(VERSION 4.2)

project(snmp_coro
    VERSION 0.1.0
    DESCRIPTION "Asio C++20 coroutine wrapper for net-snmp's SNMPv3 manager operations"
    HOMEPAGE_URL "https://github.com/lcmscheid/snmp_coro"
    LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

include(GNUInstallDirs)
include(GenerateExportHeader)
include(CMakePackageConfigHelpers)
include(SnmpCoroWarnings)

option(SNMP_CORO_BUILD_TESTS "Build unit and integration tests" ${PROJECT_IS_TOP_LEVEL})
option(SNMP_CORO_BUILD_EXAMPLES "Build examples" ${PROJECT_IS_TOP_LEVEL})
option(SNMP_CORO_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
option(SNMP_CORO_ENABLE_CLANG_TIDY "Run clang-tidy while compiling" OFF)
option(SNMP_CORO_INSTALL "Generate install and package-config rules" ${PROJECT_IS_TOP_LEVEL})

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# No C++20 modules here; skip CMake's per-source module dependency scanning.
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

if(SNMP_CORO_ENABLE_CLANG_TIDY)
    find_program(SNMP_CORO_CLANG_TIDY_EXE NAMES clang-tidy-22 clang-tidy REQUIRED)
    set(SNMP_CORO_CLANG_TIDY "${SNMP_CORO_CLANG_TIDY_EXE}")
endif()

# Supported platform: Ubuntu 26.04 LTS (Boost 1.90, net-snmp 5.9.4). Boost provides co_composed,
# any_completion_handler and system::result. CMake 4 no longer ships FindBoost; Boost's own
# BoostConfig.cmake is used.
find_package(Boost 1.90 CONFIG REQUIRED COMPONENTS headers)
find_package(NetSNMP 5.9 REQUIRED)
# USM password-to-key derivation runs in the Session constructor, on the caller's thread, so it
# uses OpenSSL directly rather than net-snmp (ADR 0001).
find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto)

add_library(snmp_coro
    src/credentials.cpp
    src/error.cpp
    src/oid.cpp
    src/session.cpp
    src/varbind.cpp)
add_library(snmp_coro::snmp_coro ALIAS snmp_coro)

generate_export_header(snmp_coro
    BASE_NAME SNMP_CORO
    EXPORT_FILE_NAME "${PROJECT_BINARY_DIR}/include/snmp_coro/export.hpp")

target_sources(snmp_coro
    PUBLIC
        FILE_SET HEADERS
        BASE_DIRS include "${PROJECT_BINARY_DIR}/include"
        FILES
            include/snmp_coro/credentials.hpp
            include/snmp_coro/error.hpp
            include/snmp_coro/oid.hpp
            include/snmp_coro/options.hpp
            include/snmp_coro/session.hpp
            include/snmp_coro/snmp_coro.hpp
            include/snmp_coro/varbind.hpp
            "${PROJECT_BINARY_DIR}/include/snmp_coro/export.hpp")

target_compile_features(snmp_coro PUBLIC cxx_std_20)
set_target_properties(snmp_coro PROPERTIES
    CXX_EXTENSIONS OFF
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    EXPORT_NAME snmp_coro)
if(NOT BUILD_SHARED_LIBS)
    target_compile_definitions(snmp_coro PUBLIC SNMP_CORO_STATIC_DEFINE)
endif()

# Boost is part of the public interface; net-snmp and OpenSSL are implementation details (ADR 0005).
target_link_libraries(snmp_coro
    PUBLIC Boost::headers
    PRIVATE NetSNMP::NetSNMP OpenSSL::Crypto)

snmp_coro_set_warnings(snmp_coro)

if(SNMP_CORO_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(SNMP_CORO_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(SNMP_CORO_INSTALL)
    install(TARGETS snmp_coro
        EXPORT snmp_coroTargets
        FILE_SET HEADERS)
    install(EXPORT snmp_coroTargets
        NAMESPACE snmp_coro::
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/snmp_coro")
    configure_package_config_file(cmake/snmp_coroConfig.cmake.in
        "${PROJECT_BINARY_DIR}/snmp_coroConfig.cmake"
        INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/snmp_coro")
    write_basic_package_version_file("${PROJECT_BINARY_DIR}/snmp_coroConfigVersion.cmake"
        COMPATIBILITY SameMinorVersion)
    install(FILES
        "${PROJECT_BINARY_DIR}/snmp_coroConfig.cmake"
        "${PROJECT_BINARY_DIR}/snmp_coroConfigVersion.cmake"
        cmake/FindNetSNMP.cmake
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/snmp_coro")
    install(FILES LICENSE DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/snmp_coro")
endif()
