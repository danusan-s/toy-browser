cmake_minimum_required(VERSION 3.10)
project(ToyBrowser)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include headers
include_directories(include)

# Gather all source files from src/
file(GLOB_RECURSE SOURCES "src/*.cpp")

# Create the executable
add_executable(browser ${SOURCES})

