/**
 * @file    monitoring_api.h
 * @brief   Публичный C-API библиотеки мониторинга (MonitoringCore.dll).
 *          Описывает общие типы данных и экспортируемые функции для
 *          взаимодействия с C# (Windows Forms) клиентским приложением.
 *
 * @note    Файл подключается как на стороне C++ (реализация), так и
 *          на стороне P/Invoke-обёртки в C#.
 */

#pragma once

#ifndef MONITORING_API_H
#define MONITORING_API_H

#include <stdint.h>  // для int64_t / uint8_t

// -----------------------------------------------------------------------
// Макрос для экспорта/импорта символов из DLL
// -----------------------------------------------------------------------
#ifdef MONITORINGCORE_EXPORTS
    #define MON_API __declspec(dllexport)
#else
    #define MON_API __declspec(dllimport)
#endif

// -----------------------------------------------------------------------
// Перечисления
// -----------------------------------------------------------------------

/// @brief Уровни критичности генерируемых событий
typedef enum AlertLevel {
    ALERT_INFO     = 0, ///< Информационное событие (подключена флешка, обычный DNS-запрос)
    ALERT_WARNING  = 1, ///< Предупреждение (заблокирована флешка)
    ALERT_CRITICAL = 2  ///< Нарушение (запрос к запрещённому домену заблокирован)
} AlertLevel;

/// @brief Идентификатор модуля-источника события
typedef enum ModuleType {
    MODULE_SYSTEM  = 0, ///< Системные события (старт/остановка сессии)
    MODULE_DNS     = 1, ///< DNS Monitor
    MODULE_USB     = 2  ///< USB Monitor
} ModuleType;

/// @brief Политика работы с USB-носителями (задаётся преподавателем)
typedef enum UsbPolicy {
    USB_POLICY_ALLOWED   = 0, ///< Разрешено, с уведомлением преподавателя (INFO алерт)
    USB_POLICY_READ_ONLY = 1, ///< Носитель монтируется только для чтения
    USB_POLICY_BLOCKED   = 2  ///< Носитель программно извлекается немедленно
} UsbPolicy;

// -----------------------------------------------------------------------
// Структуры данных
// -----------------------------------------------------------------------

/**
 * @brief Структура одного события/алерта.
 *        Передаётся через коллбек в C# при наступлении события.
 *
 * @note  Используется в P/Invoke без маршеллинга — только простые типы
 *        и фиксированные буферы (blittable).
 */
#pragma pack(push, 1)
typedef struct SystemEvent {
    ModuleType  module;         ///< Источник события
    AlertLevel  level;          ///< Уровень критичности
    int64_t     timestamp;      ///< Unix timestamp (секунды) момента события
    char        message[256];   ///< Краткое текстовое сообщение (UTF-8)
    char        details[1024];  ///< Детали в формате JSON (UTF-8)
} SystemEvent;
#pragma pack(pop)

/**
 * @brief Конфигурация сессии мониторинга.
 *        Заполняется на стороне преподавателя и передаётся в StartSession.
 */
typedef struct SessionConfig {
    // --- DNS ---
    const char** dnsWhitelist;       ///< Массив разрешённых доменов/масок (например "*.google.com")
    int          dnsWhitelistCount;  ///< Количество элементов в dnsWhitelist

    // --- USB ---
    UsbPolicy    usbPolicy;          ///< Политика для USB-носителей
} SessionConfig;

// -----------------------------------------------------------------------
// Тип коллбека для событий
// -----------------------------------------------------------------------

/**
 * @brief Тип функции обратного вызова, которую C# регистрирует для приёма событий.
 *
 * @param eventData  Указатель на структуру события (время жизни — только на
 *                   время вызова; C# должен скопировать данные если нужно хранить).
 *
 * @note  В C# объявляется как:
 *        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
 *        delegate void EventCallback(ref SystemEvent eventData);
 */
typedef void(__cdecl* EventCallback)(const SystemEvent* eventData);

// -----------------------------------------------------------------------
// Экспортируемые функции (C-API)
// -----------------------------------------------------------------------
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  Инициализирует оба модуля и регистрирует коллбек для событий.
 *         Должна быть вызвана ПЕРВОЙ, до StartSession.
 *
 * @param  callback  Указатель на функцию-коллбек (реализована на стороне C#).
 * @return TRUE при успехе, FALSE при ошибке инициализации.
 */
MON_API int __cdecl InitModules(EventCallback callback);

/**
 * @brief  Запускает сессию мониторинга с указанными правилами.
 *         Активирует DNS-перехват и USB-слежение.
 *
 * @param  config  Указатель на структуру конфигурации сессии.
 * @return TRUE при успехе.
 */
MON_API int __cdecl StartSession(const SessionConfig* config);

/**
 * @brief  Останавливает активную сессию (снимает хуки, освобождает уведомления).
 *         Модули остаются инициализированными — StartSession можно вызвать снова.
 */
MON_API void __cdecl StopSession(void);

/**
 * @brief  Полное освобождение ресурсов. Вызывается при закрытии приложения.
 */
MON_API void __cdecl ShutdownModules(void);

/**
 * @brief  Возвращает агрегированный JSON-отчёт об инцидентах за сессию.
 *
 * @param  outJsonBuffer  Буфер, куда будет записан JSON (null-terminated UTF-8).
 * @param  bufferSize     Размер буфера в байтах.
 * @return TRUE если буфер достаточного размера и данные записаны.
 */
MON_API int __cdecl GetSessionReport(char* outJsonBuffer, int bufferSize);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // MONITORING_API_H
