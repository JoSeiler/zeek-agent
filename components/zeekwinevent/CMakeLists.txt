cmake_minimum_required(VERSION 3.16.3)
project("zeek_winevent")

function(zeekAgentComponentsWinEvent)

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

    add_library("${PROJECT_NAME}"
            include/zeek/iwineventconsumer.h

            src/windows_utils.h
            src/windows_utils.cpp

            src/winevtlogparser.h
            src/winevtlogparser.cpp

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
            )

    target_include_directories("${PROJECT_NAME}"
            PRIVATE include
            )

    target_include_directories("${PROJECT_NAME}"
            SYSTEM INTERFACE include
            )

    #generateZeekAgentTest(
    #        SOURCE_TARGET
    #        "${PROJECT_NAME}"

    #        SOURCES
    #        tests/main.cpp
    #        tests/wineventconsumer.cpp
    #)
endfunction()

zeekAgentComponentsWinEvent()
