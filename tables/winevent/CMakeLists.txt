cmake_minimum_required(VERSION 3.16.3)

function(zeekAgentTablesWinEvent)

    set (BOOST_ROOT "C:/Program Files/libs/boost_1_75_0")
    set (BOOST_INCLUDEDIR "C:/Program Files/libs/boost_1_75_0")
    set (BOOST_LIBRARYDIR "C:/Program Files/libs/boost_1_75_0/lib")
    set (BOOST_MIN_VERSION "1.75.0")
    set (Boost_NO_BOOST_CMAKE ON)

    find_package(Boost ${BOOST_MIN_VERSION} REQUIRED)

    if (NOT Boost_FOUND)
        message(FATAL_ERROR "Fatal error: Boost (version >= 1.75) required.")
    else()
        message(STATUS "Setting up BOOST")
        message(STATUS " Includes - ${Boost_INCLUDE_DIRS}")
        message(STATUS " Library  - ${Boost_LIBRARY_DIRS}")
        include_directories(${Boost_INCLUDE_DIRS})
        link_directories(${Boost_LIBRARY_DIRS})
    endif (NOT Boost_FOUND)

    add_library(zeek_winevent_tables
            include/zeek/winevtlogservicefactory.h
            src/winevtlogservicefactory.cpp

            src/networkconntableplugin.h
            src/networkconntableplugin.cpp

            src/processcreationtableplugin.h
            src/processcreationtableplugin.cpp

            src/processterminationtableplugin.h
            src/processterminationtableplugin.cpp

            src/filemonitoringtableplugin.h
            src/filemonitoringtableplugin.cpp

            src/regvalmodifiedtableplugin.h
            src/regvalmodifiedtableplugin.cpp

            src/winevtlogservice.h
            src/winevtlogservice.cpp
            )

    target_include_directories(zeek_winevent_tables PRIVATE
            include
            )

    target_include_directories(zeek_winevent_tables SYSTEM INTERFACE
            include
            )

    target_link_libraries(zeek_winevent_tables PUBLIC
            zeek_winevent
            zeek_database
            zeek_configuration
            zeek_service_manager
            )

    target_link_libraries(zeek_tables INTERFACE zeek_winevent_tables)

    #generateZeekAgentTest(
    #        SOURCE_TARGET
    #        "zeek_winevent_tables"

    #        SOURCES
    #        tests/main.cpp

    #        tests/socketeventstableplugin.cpp
    #        tests/processeventstableplugin.cpp
    #)
endfunction()

zeekAgentTablesWinEvent()
