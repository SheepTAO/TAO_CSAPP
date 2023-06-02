include_directories(cpu)
include_directories(disk)
include_directories(memory)

aux_source_directory(cpu CPU_SOURCES)
aux_source_directory(disk DISK_SOURCES)
aux_source_directory(memory MEMORY_SOURCES)

add_executable(avc main.cpp ${CPU_SOURCES} ${DISK_SOURCES} ${MEMORY_SOURCES})