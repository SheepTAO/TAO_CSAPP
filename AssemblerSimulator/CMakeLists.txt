include_directories(headers)

aux_source_directory(hardware/cpu CPU_SOURCES)
aux_source_directory(hardware/memory MEMORY_SOURCES)
aux_source_directory(common COMMON_SOURCES)

add_executable(avc main.cpp ${CPU_SOURCES} ${MEMORY_SOURCES} ${COMMON_SOURCES})