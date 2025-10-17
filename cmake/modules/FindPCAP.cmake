# FindPCAP.cmake - Find libpcap library
# This module defines:
#  PCAP_FOUND - system has libpcap
#  PCAP_INCLUDE_DIRS - the libpcap include directory
#  PCAP_LIBRARIES - Link these to use libpcap
#  PCAP_VERSION - libpcap version

find_path(PCAP_INCLUDE_DIR
    NAMES pcap.h
    PATHS /usr/include /usr/local/include
)

find_library(PCAP_LIBRARY
    NAMES pcap wpcap
    PATHS /usr/lib /usr/local/lib
)

if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
    # Try to find version
    if(EXISTS "${PCAP_INCLUDE_DIR}/pcap.h")
        file(STRINGS "${PCAP_INCLUDE_DIR}/pcap.h" PCAP_VERSION_LINE
            REGEX "^#define[ \t]+PCAP_VERSION_MAJOR[ \t]+[0-9]+")
        if(PCAP_VERSION_LINE)
            string(REGEX REPLACE "^#define[ \t]+PCAP_VERSION_MAJOR[ \t]+([0-9]+)" "\\1"
                PCAP_VERSION_MAJOR "${PCAP_VERSION_LINE}")
        endif()

        file(STRINGS "${PCAP_INCLUDE_DIR}/pcap.h" PCAP_VERSION_LINE
            REGEX "^#define[ \t]+PCAP_VERSION_MINOR[ \t]+[0-9]+")
        if(PCAP_VERSION_LINE)
            string(REGEX REPLACE "^#define[ \t]+PCAP_VERSION_MINOR[ \t]+([0-9]+)" "\\1"
                PCAP_VERSION_MINOR "${PCAP_VERSION_LINE}")
        endif()

        if(PCAP_VERSION_MAJOR AND PCAP_VERSION_MINOR)
            set(PCAP_VERSION "${PCAP_VERSION_MAJOR}.${PCAP_VERSION_MINOR}")
        endif()
    endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP
    REQUIRED_VARS PCAP_LIBRARY PCAP_INCLUDE_DIR
    VERSION_VAR PCAP_VERSION
)

if(PCAP_FOUND)
    set(PCAP_LIBRARIES ${PCAP_LIBRARY})
    set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
    mark_as_advanced(PCAP_INCLUDE_DIR PCAP_LIBRARY)
endif()
