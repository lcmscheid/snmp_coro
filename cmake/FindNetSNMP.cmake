# FindNetSNMP
# -----------
# Finds the net-snmp client library.
#
# Imported target:  NetSNMP::NetSNMP
# Result variables: NetSNMP_FOUND, NetSNMP_VERSION, NetSNMP_INCLUDE_DIRS, NetSNMP_LIBRARIES
#
# pkg-config ("netsnmp") is preferred; otherwise the headers and library are searched for and the
# version is read from net-snmp-config.h.

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PC_NetSNMP QUIET netsnmp)
endif()

find_path(NetSNMP_INCLUDE_DIR
    NAMES net-snmp/net-snmp-config.h
    HINTS ${PC_NetSNMP_INCLUDEDIR} ${PC_NetSNMP_INCLUDE_DIRS})
find_library(NetSNMP_LIBRARY
    NAMES netsnmp
    HINTS ${PC_NetSNMP_LIBDIR} ${PC_NetSNMP_LIBRARY_DIRS})

if(PC_NetSNMP_VERSION)
    set(NetSNMP_VERSION "${PC_NetSNMP_VERSION}")
elseif(NetSNMP_INCLUDE_DIR AND EXISTS "${NetSNMP_INCLUDE_DIR}/net-snmp/net-snmp-config.h")
    file(STRINGS "${NetSNMP_INCLUDE_DIR}/net-snmp/net-snmp-config.h" _netsnmp_version_line
        REGEX "^#define PACKAGE_VERSION \"[^\"]+\"")
    string(REGEX REPLACE "^#define PACKAGE_VERSION \"([0-9.]+).*" "\\1" NetSNMP_VERSION
        "${_netsnmp_version_line}")
    unset(_netsnmp_version_line)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(NetSNMP
    REQUIRED_VARS NetSNMP_LIBRARY NetSNMP_INCLUDE_DIR
    VERSION_VAR NetSNMP_VERSION)

if(NetSNMP_FOUND)
    set(NetSNMP_INCLUDE_DIRS "${NetSNMP_INCLUDE_DIR}")
    set(NetSNMP_LIBRARIES "${NetSNMP_LIBRARY}")
    if(NOT TARGET NetSNMP::NetSNMP)
        add_library(NetSNMP::NetSNMP UNKNOWN IMPORTED)
        # SYSTEM: net-snmp's headers are not warning-clean under our flags.
        set_target_properties(NetSNMP::NetSNMP PROPERTIES
            IMPORTED_LOCATION "${NetSNMP_LIBRARY}"
            INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${NetSNMP_INCLUDE_DIR}"
            INTERFACE_INCLUDE_DIRECTORIES "${NetSNMP_INCLUDE_DIR}")
    endif()
endif()

mark_as_advanced(NetSNMP_INCLUDE_DIR NetSNMP_LIBRARY)
