cmake_minimum_required(VERSION 3.24)
project(claudex_windows_shim C)

if(NOT WIN32 OR NOT MSVC)
  message(FATAL_ERROR "The Claudex native launcher requires the Microsoft Windows toolchain")
endif()

add_executable(claudex-shim src/main.c src/quote.c)
target_include_directories(claudex-shim PRIVATE src)
target_compile_definitions(claudex-shim PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
target_compile_options(claudex-shim PRIVATE /W4 /WX /O2 /guard:cf /sdl)
target_link_options(claudex-shim PRIVATE /DYNAMICBASE /NXCOMPAT /guard:cf)
target_link_libraries(claudex-shim PRIVATE bcrypt)

add_executable(capture-child test/capture-child.c)
target_compile_definitions(capture-child PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
target_compile_options(capture-child PRIVATE /W4 /WX /O2 /guard:cf /sdl)
target_link_options(capture-child PRIVATE /DYNAMICBASE /NXCOMPAT /guard:cf)
