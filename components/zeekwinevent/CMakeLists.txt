cmake_minimum_required(VERSION 3.16.3)
project("zeek_winevent")

function(zeekAgentComponentsWinEvent)
    add_library("${PROJECT_NAME}"
            include/zeek/iwineventconsumer.h

            src/wineventconsumer.h
            src/wineventconsumer.cpp
            )

    target_link_libraries("${PROJECT_NAME}"
            PRIVATE
            zeek_agent_cxx_settings

            PUBLIC
            zeek_utils
            zeek_logger
            zeek_configuration

            thirdparty_winevent
            )

    target_include_directories("${PROJECT_NAME}"
            PRIVATE include
            )

    target_include_directories("${PROJECT_NAME}"
            SYSTEM INTERFACE include
            )

    generateZeekAgentTest(
            SOURCE_TARGET
            "${PROJECT_NAME}"

            SOURCES
            tests/main.cpp
            tests/wineventconsumer.cpp
    )
endfunction()

zeekAgentComponentsWinEvent()
