# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.20

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/ariane/Desktop/clion-2020.3.2/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /home/ariane/Desktop/clion-2020.3.2/bin/cmake/linux/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/ariane/Documents/projetosTCC2/ServidorSistema

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ariane/Documents/projetosTCC2/ServidorSistema/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/ServidorSistema.dir/depend.make
# Include the progress variables for this target.
include CMakeFiles/ServidorSistema.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/ServidorSistema.dir/flags.make

CMakeFiles/ServidorSistema.dir/main.c.o: CMakeFiles/ServidorSistema.dir/flags.make
CMakeFiles/ServidorSistema.dir/main.c.o: ../main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ariane/Documents/projetosTCC2/ServidorSistema/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/ServidorSistema.dir/main.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/ServidorSistema.dir/main.c.o -c /home/ariane/Documents/projetosTCC2/ServidorSistema/main.c

CMakeFiles/ServidorSistema.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ServidorSistema.dir/main.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ariane/Documents/projetosTCC2/ServidorSistema/main.c > CMakeFiles/ServidorSistema.dir/main.c.i

CMakeFiles/ServidorSistema.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ServidorSistema.dir/main.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ariane/Documents/projetosTCC2/ServidorSistema/main.c -o CMakeFiles/ServidorSistema.dir/main.c.s

# Object files for target ServidorSistema
ServidorSistema_OBJECTS = \
"CMakeFiles/ServidorSistema.dir/main.c.o"

# External object files for target ServidorSistema
ServidorSistema_EXTERNAL_OBJECTS =

ServidorSistema: CMakeFiles/ServidorSistema.dir/main.c.o
ServidorSistema: CMakeFiles/ServidorSistema.dir/build.make
ServidorSistema: CMakeFiles/ServidorSistema.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ariane/Documents/projetosTCC2/ServidorSistema/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable ServidorSistema"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/ServidorSistema.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/ServidorSistema.dir/build: ServidorSistema
.PHONY : CMakeFiles/ServidorSistema.dir/build

CMakeFiles/ServidorSistema.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/ServidorSistema.dir/cmake_clean.cmake
.PHONY : CMakeFiles/ServidorSistema.dir/clean

CMakeFiles/ServidorSistema.dir/depend:
	cd /home/ariane/Documents/projetosTCC2/ServidorSistema/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ariane/Documents/projetosTCC2/ServidorSistema /home/ariane/Documents/projetosTCC2/ServidorSistema /home/ariane/Documents/projetosTCC2/ServidorSistema/cmake-build-debug /home/ariane/Documents/projetosTCC2/ServidorSistema/cmake-build-debug /home/ariane/Documents/projetosTCC2/ServidorSistema/cmake-build-debug/CMakeFiles/ServidorSistema.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/ServidorSistema.dir/depend

