include(FetchContent)
# Prefer an installed Catch2 v3; fall back to fetching a pinned release.
FetchContent_Declare(Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.7.1
    GIT_SHALLOW TRUE
    FIND_PACKAGE_ARGS 3 CONFIG)
FetchContent_MakeAvailable(Catch2)
include(Catch)

# Catch2's TEST_CASE/SECTION macros expand __COUNTER__, which Clang 22's -Wpedantic reports as a
# C2y extension at every use site in our test files.
function(snmp_coro_catch2_flags target)
    target_compile_options(${target} PRIVATE $<$<CXX_COMPILER_ID:Clang>:-Wno-c2y-extensions>)
endfunction()

# --- unit tests: no network, no agent -------------------------------------------------------
add_executable(snmp_coro_unit_tests
    unit/credentials_test.cpp
    unit/error_test.cpp
    unit/oid_test.cpp
    unit/session_test.cpp
    unit/varbind_test.cpp)
target_link_libraries(snmp_coro_unit_tests PRIVATE snmp_coro::snmp_coro Catch2::Catch2WithMain)
snmp_coro_set_warnings(snmp_coro_unit_tests)
snmp_coro_catch2_flags(snmp_coro_unit_tests)
catch_discover_tests(snmp_coro_unit_tests
    TEST_PREFIX "unit."
    PROPERTIES LABELS unit)

# --- integration tests: a real snmpd started by the test binary ------------------------------
find_program(SNMP_CORO_SNMPD snmpd PATHS /usr/sbin /usr/local/sbin)
if(NOT SNMP_CORO_SNMPD)
    message(WARNING "snmpd not found: integration tests will be skipped at run time")
    set(SNMP_CORO_SNMPD "")
endif()

add_executable(snmp_coro_integration_tests
    integration/agent.cpp
    integration/errors_test.cpp
    integration/operations_test.cpp
    integration/recovery_test.cpp
    integration/session_lifecycle_test.cpp)
target_link_libraries(snmp_coro_integration_tests PRIVATE snmp_coro::snmp_coro Catch2::Catch2WithMain)
target_compile_definitions(snmp_coro_integration_tests PRIVATE
    SNMP_CORO_SNMPD="${SNMP_CORO_SNMPD}")
snmp_coro_set_warnings(snmp_coro_integration_tests)
snmp_coro_catch2_flags(snmp_coro_integration_tests)

catch_discover_tests(snmp_coro_integration_tests
    TEST_PREFIX "integration."
    PROPERTIES
        LABELS integration
        SKIP_RETURN_CODE 4
    DISCOVERY_MODE PRE_TEST)
