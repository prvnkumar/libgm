# The name of our project is "libgm". CMakeLists files in this project can
# refer to the root source directory of the project as ${LIBGM_SOURCE_DIR} and
# to the root binary directory of the project as ${LIBGM_BINARY_DIR}.
cmake_minimum_required (VERSION 2.6)
project (LIBGM)
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
set(CMAKE_BUILD_TYPE Debug)
# disallow in-source build
include(MacroEnsureOutOfSourceBuild)
macro_ensure_out_of_source_build("${PROJECT_NAME} requires an out of source build. Please create a separate build directory and run 'cmake /path/to/${PROJECT_NAME} [options]' there.")


# Recurse into the "Hello" and "Demo" subdirectories. This does not actually
# cause another cmake executable to run. The same process will walk through
# the project's entire directory structure.
add_subdirectory (libgm)
add_subdirectory (testgm) 
