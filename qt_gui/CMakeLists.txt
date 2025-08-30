cmake_minimum_required(VERSION 3.5)
project(MythwareToolkitQt)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)

find_package(Qt5 REQUIRED COMPONENTS Widgets)

add_executable(MythwareToolkitQt
    main.cpp
    mainwindow.cpp
    mainwindow.h)

target_link_libraries(MythwareToolkitQt Qt5::Widgets)
