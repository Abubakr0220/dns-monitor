# CMakeLists.txt для MonitoringCore.dll
# -----------------------------------------------------------------------
# Требования:
#   - CMake >= 3.20
#   - MSVC (Visual Studio 2019 или 2022), сборка x64
#   - MinHook: скачай с https://github.com/TsudaKageyu/minhook/releases
#     Распакуй так, чтобы получилось:
#       third_party/minhook/include/MinHook.h
#       third_party/minhook/lib/MinHook.x64.lib  (или MinHook.x64.dll + .lib)
# -----------------------------------------------------------------------

cmake_minimum_required(VERSION 3.20)
project(MonitoringCore VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# -----------------------------------------------------------------------
# Исходные файлы библиотеки
# -----------------------------------------------------------------------
set(MONITORING_SOURCES
    src/dns_monitor.cpp
    src/usb_monitor.cpp
    src/library_exports.cpp
)

set(MONITORING_HEADERS
    include/monitoring_api.h
    include/dns_monitor.h
    include/usb_monitor.h
)

# -----------------------------------------------------------------------
# Основная цель — Shared Library (DLL)
# -----------------------------------------------------------------------
add_library(MonitoringCore SHARED
    ${MONITORING_SOURCES}
    ${MONITORING_HEADERS}
)

# Экспорт символов
target_compile_definitions(MonitoringCore PRIVATE
    MONITORINGCORE_EXPORTS
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS  # для strncpy_s без предупреждений
)

# Заголовочные файлы проекта
target_include_directories(MonitoringCore PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# MinHook headers
target_include_directories(MonitoringCore PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/minhook/include
)

# -----------------------------------------------------------------------
# Системные Windows библиотеки
# -----------------------------------------------------------------------
target_link_libraries(MonitoringCore PRIVATE
    dnsapi      # DnsQuery_A, DnsFlushResolverCache
    ws2_32      # getaddrinfo, Winsock
    setupapi    # SetupDiGetClassDevs (SetupAPI для USB)
    cfgmgr32    # CM_Request_Device_EjectW
)

# MinHook статическая библиотека
target_link_libraries(MonitoringCore PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/minhook/lib/MinHook.x64.lib
)

# -----------------------------------------------------------------------
# Настройки компилятора MSVC
# -----------------------------------------------------------------------
if(MSVC)
    target_compile_options(MonitoringCore PRIVATE
        /W4         # Высокий уровень предупреждений
        /WX-        # Не превращать предупреждения в ошибки (пока разрабатываем)
        /MP         # Параллельная компиляция
    )

    # Генерить .pdb файл для отладки
    target_compile_options(MonitoringCore PRIVATE $<$<CONFIG:Debug>:/Zi>)
    target_link_options(MonitoringCore PRIVATE $<$<CONFIG:Debug>:/DEBUG>)
endif()

# -----------------------------------------------------------------------
# Выходной файл в корне build/
# -----------------------------------------------------------------------
set_target_properties(MonitoringCore PROPERTIES
    OUTPUT_NAME "MonitoringCore"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

# -----------------------------------------------------------------------
# Сборка (из корня проекта):
#   cmake -B build -G "Visual Studio 17 2022" -A x64
#   cmake --build build --config Release
# -----------------------------------------------------------------------
