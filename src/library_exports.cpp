/**
 * @file    library_exports.cpp
 * @brief   Реализация экспортируемых C-функций DLL-библиотеки (MonitoringCore.dll).
 *          Это "клей" — Bridge между C-API (вызывается из C# через P/Invoke)
 *          и внутренними классами DnsMonitor / UsbMonitor.
 *
 * @note    Определение MONITORINGCORE_EXPORTS должно передаваться компилятору
 *          только при сборке самой DLL (в настройках проекта: Preprocessor Definitions).
 *          Клиентский код подключает только monitoring_api.h и линкуется к .lib.
 */

#define MONITORINGCORE_EXPORTS
#include "monitoring_api.h"
#include "dns_monitor.h"
#include "usb_monitor.h"

#include <cstring>  // strncpy_s
#include <string>

// -----------------------------------------------------------------------
// Вспомогательные функции (внутренние, не экспортируются)
// -----------------------------------------------------------------------

/**
 * @brief  Объединяет JSON-отчёты обоих модулей в единый объект.
 *
 * @param  out           Буфер для финального JSON
 * @param  bufferSize    Размер буфера
 * @return true если данные уместились в буфер
 */
static bool BuildCombinedReport(char* out, int bufferSize) {
    std::string dnsJson, usbJson;
    DnsMonitor::GetInstance().GetReport(dnsJson);
    UsbMonitor::GetInstance().GetReport(usbJson);

    // Собираем единый JSON-объект
    std::string combined = "{\n  \"dns\": " + dnsJson + ",\n  \"usb\": " + usbJson + "\n}";

    if (static_cast<int>(combined.size()) + 1 > bufferSize) {
        return false; // Буфер слишком мал
    }

    strncpy_s(out, bufferSize, combined.c_str(), _TRUNCATE);
    return true;
}

// -----------------------------------------------------------------------
// Реализация экспортируемого C-API
// -----------------------------------------------------------------------

/**
 * @brief  InitModules — инициализирует оба модуля и регистрирует коллбек.
 *
 * Вызывает Initialize() для DnsMonitor и UsbMonitor.
 * Если хотя бы один модуль не инициализировался — возвращает FALSE.
 */
extern "C" MON_API int __cdecl InitModules(EventCallback callback) {
    if (callback == nullptr) {
        return FALSE;
    }

    bool dnsOk = DnsMonitor::GetInstance().Initialize(callback);
    bool usbOk = UsbMonitor::GetInstance().Initialize(callback);

    return (dnsOk && usbOk) ? TRUE : FALSE;
}

/**
 * @brief  StartSession — запускает сессию мониторинга с заданными правилами.
 *
 * Применяет SessionConfig к соответствующим модулям:
 *  - dnsWhitelist -> DnsMonitor::Start()
 *  - usbPolicy    -> UsbMonitor::Start()
 */
extern "C" MON_API int __cdecl StartSession(const SessionConfig* config) {
    if (config == nullptr) {
        return FALSE;
    }

    // Конвертируем C-массив строк в std::vector<std::string>
    std::vector<std::string> whitelist;
    whitelist.reserve(static_cast<size_t>(config->dnsWhitelistCount));
    for (int i = 0; i < config->dnsWhitelistCount; ++i) {
        if (config->dnsWhitelist[i] != nullptr) {
            whitelist.emplace_back(config->dnsWhitelist[i]);
        }
    }

    bool dnsOk = DnsMonitor::GetInstance().Start(whitelist);
    bool usbOk = UsbMonitor::GetInstance().Start(config->usbPolicy);

    return (dnsOk && usbOk) ? TRUE : FALSE;
}

/**
 * @brief  StopSession — останавливает активную сессию.
 *         Вызывает Stop() у обоих модулей. Статистика сохраняется.
 */
extern "C" MON_API void __cdecl StopSession(void) {
    DnsMonitor::GetInstance().Stop();
    UsbMonitor::GetInstance().Stop();
}

/**
 * @brief  ShutdownModules — полное освобождение ресурсов (MinHook, окна, хэндлы).
 *         Обязателен перед выгрузкой DLL.
 */
extern "C" MON_API void __cdecl ShutdownModules(void) {
    DnsMonitor::GetInstance().Uninitialize();
    UsbMonitor::GetInstance().Uninitialize();
}

/**
 * @brief  GetSessionReport — возвращает агрегированный JSON-отчёт за сессию.
 *
 * @param  outJsonBuffer  Буфер для JSON (должен быть выделен вызывающей стороной).
 *                        Рекомендуемый размер: 65536 байт (64 КБ).
 * @param  bufferSize     Размер буфера в байтах.
 * @return TRUE если данные успешно записаны в буфер.
 */
extern "C" MON_API int __cdecl GetSessionReport(char* outJsonBuffer, int bufferSize) {
    if (outJsonBuffer == nullptr || bufferSize <= 0) {
        return FALSE;
    }
    return BuildCombinedReport(outJsonBuffer, bufferSize) ? TRUE : FALSE;
}
