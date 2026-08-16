cmake_minimum_required(VERSION 3.24)
project(claudey_windows_shim C)

if(NOT WIN32 OR NOT MSVC)
  message(FATAL_ERROR "The Claudey native launcher requires the Microsoft Windows toolchain")
endif()

add_executable(claudey-shim src/main.c src/quote.c)
target_include_directories(claudey-shim PRIVATE src)
target_compile_definitions(claudey-shim PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
target_compile_options(claudey-shim PRIVATE /W4 /WX /O2 /guard:cf /sdl)
target_link_options(claudey-shim PRIVATE /DYNAMICBASE /NXCOMPAT /guard:cf)
target_link_libraries(claudey-shim PRIVATE bcrypt)

add_executable(capture-child test/capture-child.c)
target_compile_definitions(capture-child PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
target_compile_options(capture-child PRIVATE /W4 /WX /O2 /guard:cf /sdl)
target_link_options(capture-child PRIVATE /DYNAMICBASE /NXCOMPAT /guard:cf)
