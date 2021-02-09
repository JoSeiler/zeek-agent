cmake_minimum_required(VERSION 3.16.3)

function(zeekAgentTablesWinEvent)
    add_library(zeek_winevent_tables
            include/zeek/wineventservicefactory.h
            src/wineventservicefactory.cpp

            src/socketeventstableplugin.h
            src/socketeventstableplugin.cpp

            #src/processeventstableplugin.h
            #src/processeventstableplugin.cpp

            src/wineventservice.h
            src/wineventservice.cpp
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
