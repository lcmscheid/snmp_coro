add_executable(snmp_coro_walk walk.cpp)
target_link_libraries(snmp_coro_walk PRIVATE snmp_coro::snmp_coro)
snmp_coro_set_warnings(snmp_coro_walk)
