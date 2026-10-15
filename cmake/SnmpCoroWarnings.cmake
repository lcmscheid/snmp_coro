# snmp_coro_set_warnings(<target>)
# Applies the project's warning set (and clang-tidy, when enabled) to one of our own targets,
# never to dependencies such as a fetched Catch2.

function(snmp_coro_set_warnings target)
    set(_gnu_common
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wconversion
        -Wsign-conversion
        -Wold-style-cast
        -Wnon-virtual-dtor
        -Woverloaded-virtual
        -Wcast-align
        -Wnull-dereference
        -Wdouble-promotion
        -Wformat=2
        -Wimplicit-fallthrough
        -Wextra-semi)
    set(_gcc_only
        -Wduplicated-cond
        -Wduplicated-branches
        -Wlogical-op
        -Wuseless-cast)
    set(_msvc
        /W4
        /permissive-)

    target_compile_options(${target} PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:${_gnu_common}>
        $<$<CXX_COMPILER_ID:GNU>:${_gcc_only}>
        $<$<CXX_COMPILER_ID:MSVC>:${_msvc}>)

    if(SNMP_CORO_WARNINGS_AS_ERRORS)
        set_target_properties(${target} PROPERTIES COMPILE_WARNING_AS_ERROR ON)
    endif()
    if(SNMP_CORO_ENABLE_CLANG_TIDY)
        set_target_properties(${target} PROPERTIES CXX_CLANG_TIDY "${SNMP_CORO_CLANG_TIDY}")
    endif()
endfunction()
