/**
 * @file    usb_monitor.h
 * @brief   Объявление класса UsbMonitor — модуля обнаружения и управления
 *          USB-носителями (флешками, внешними дисками).
 *
 * Механизм обнаружения: Message-Only Window + RegisterDeviceNotification (WM_DEVICECHANGE).
 * Поддерживаемые политики (UsbPolicy из monitoring_api.h):
 *   - USB_POLICY_ALLOWED   — подключение разрешено, INFO алерт отправляется преподавателю
 *   - USB_POLICY_READ_ONLY — устройство монтируется только для чтения (реестр WriteProtect)
 *   - USB_POLICY_BLOCKED   — устройство программно извлекается (DeviceIoControl / CM_Request_Device_Eject)
 *
 * @note  Потребует права Администратора для режимов READ_ONLY и BLOCKED.
 *        Класс является синглтоном (один Message Loop на процесс).
 */

#pragma once

#ifndef USB_MONITOR_H
#define USB_MONITOR_H

#include "monitoring_api.h"

#ifdef __cplusplus

#include <Windows.h>
#include <dbt.h>          // WM_DEVICECHANGE, DEV_BROADCAST_HDR, GUID_DEVINTERFACE_*
#include <setupapi.h>     // SetupDiGetClassDevs (понадобится для SetupAPI на Этапе 3)
#include <cfgmgr32.h>     // CM_Request_Device_EjectW
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <thread>

/**
 * @brief Состояние подключённого носителя
 */
enum class UsbDeviceState {
    CONNECTED,    ///< Носитель подключён в данный момент
    DISCONNECTED, ///< Носитель был извлечён
    EJECTED       ///< Носитель был программно извлечён системой мониторинга
};

/**
 * @brief Метаданные об одном USB-носителе
 */
struct UsbDeviceInfo {
    std::string   driveLetter;    ///< Буква диска, например "F:"
    std::string   volumeLabel;    ///< Метка тома ("MyFlash")
    std::string   volumeSerialHex;///< Серийный номер тома в hex ("A1B2C3D4")
    uint64_t      totalBytes;     ///< Полный объём носителя в байтах
    uint64_t      freeBytes;      ///< Свободное место на носителе в байтах
    int64_t       connectedAt;    ///< Unix timestamp момента подключения
    int64_t       disconnectedAt; ///< Unix timestamp момента отключения (0 если ещё подкл.)
    UsbDeviceState state;         ///< Текущее состояние
};

/**
 * @class UsbMonitor
 * @brief Слушает WM_DEVICECHANGE, собирает метаданные о носителях,
 *        применяет политику и отправляет алерты через EventCallback.
 *
 * Жизненный цикл:
 *   UsbMonitor::GetInstance() -> Initialize(callback) -> Start(policy) -> ... -> Stop() -> Uninitialize()
 */
class UsbMonitor {
public:
    // -----------------------------------------------------------------------
    // Синглтон
    // -----------------------------------------------------------------------

    /// @brief Получить единственный экземпляр класса
    static UsbMonitor& GetInstance();

    // Запрет копирования
    UsbMonitor(const UsbMonitor&) = delete;
    UsbMonitor& operator=(const UsbMonitor&) = delete;

    // -----------------------------------------------------------------------
    // Управление жизненным циклом
    // -----------------------------------------------------------------------

    /**
     * @brief  Инициализирует класс и регистрирует коллбек для событий.
     *         Ещё не запускает Message Loop.
     *
     * @param  callback  Функция-приёмник событий (реализована в C#).
     * @return true при успехе.
     */
    bool Initialize(EventCallback callback);

    /**
     * @brief  Запускает мониторинг USB:
     *         1. Создаёт Message-Only Window в отдельном потоке
     *         2. Регистрирует уведомления о подключении/отключении устройств класса
     *            GUID_DEVINTERFACE_VOLUME (тома дисков)
     *         3. Применяет политику ко всем уже подключённым носителям
     *
     * @param  policy  Политика обработки носителей на эту сессию.
     * @return true при успехе.
     */
    bool Start(UsbPolicy policy);

    /**
     * @brief  Останавливает мониторинг: снимает уведомления, завершает Message Loop,
     *         дожидается завершения рабочего потока.
     */
    void Stop();

    /**
     * @brief  Освобождает все ресурсы Windows. Вызывается при Shutdown.
     */
    void Uninitialize();

    // -----------------------------------------------------------------------
    // Отчётность
    // -----------------------------------------------------------------------

    /**
     * @brief  Формирует JSON-строку с итогами сессии по USB.
     *
     * Формат JSON:
     * @code
     * {
     *   "module": "USB",
     *   "policy": "BLOCKED",
     *   "total_events": 3,
     *   "devices": [
     *     {
     *       "drive": "F:",
     *       "label": "Transcend",
     *       "serial": "A1B2C3D4",
     *       "total_gb": 14.9,
     *       "state": "EJECTED",
     *       "connected_at": 1710000000,
     *       "disconnected_at": 1710000005
     *     }
     *   ]
     * }
     * @endcode
     *
     * @param  out  Строка, в которую будет записан JSON.
     */
    void GetReport(std::string& out) const;

    /**
     * @brief  Отправляет тестовый INFO-алерт о "подключении флешки".
     *         Для отладки GUI без реального устройства.
     */
    void SendTestEvent();

private:
    UsbMonitor();
    ~UsbMonitor();

    // -----------------------------------------------------------------------
    // Внутренние методы
    // -----------------------------------------------------------------------

    /**
     * @brief  Тело рабочего потока — Message Loop для невидимого окна.
     */
    void MessagePumpThread();

    /**
     * @brief  Статическая WndProc, делегирует вызов в HandleMessage().
     */
    static LRESULT CALLBACK StaticWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    /**
     * @brief  Обработчик WM_DEVICECHANGE для конкретного экземпляра класса.
     *
     * @param  wParam  DBT_DEVICEARRIVAL / DBT_DEVICEREMOVECOMPLETE и т.д.
     * @param  lParam  Указатель на DEV_BROADCAST_HDR
     */
    LRESULT HandleDeviceChange(WPARAM wParam, LPARAM lParam);

    /**
     * @brief  Вызывается при DBT_DEVICEARRIVAL для тома (буква диска).
     *         Собирает метаданные, логирует, применяет политику.
     */
    void OnVolumeArrival(char driveLetter);

    /**
     * @brief  Вызывается при DBT_DEVICEREMOVECOMPLETE.
     */
    void OnVolumeRemoved(char driveLetter);

    /**
     * @brief  Применяет текущую политику к только что подключённому тому.
     *         ALLOWED -> FireEvent(INFO), READ_ONLY -> SetWriteProtect(), BLOCKED -> EjectVolume()
     */
    void ApplyPolicy(const UsbDeviceInfo& device);

    /**
     * @brief  Программно извлекает носитель через DeviceIoControl(FSCTL_DISMOUNT_VOLUME)
     *         и CM_Request_Device_EjectW. Затем шлёт WARNING алерт.
     *
     * @param  driveLetter  Буква диска ('F', 'G' и т.д.)
     * @return true если извлечение прошло успешно
     */
    bool EjectVolume(char driveLetter);

    /**
     * @brief  Устанавливает защиту от записи для класса USB Mass Storage
     *         через ключ реестра WriteProtect.
     *         Требует перемонтирование для уже подключённых устройств.
     *
     * @param  protect  true — запрет записи, false — разрешить запись
     * @return true при успехе
     */
    static bool SetUsbWriteProtect(bool protect);

    /**
     * @brief  Собирает метаданные о томе через GetVolumeInformationA.
     *
     * @param  driveLetter  Буква диска
     * @param  out          Структура, которая будет заполнена данными
     * @return true при успехе
     */
    static bool CollectDeviceInfo(char driveLetter, UsbDeviceInfo& out);

    /**
     * @brief  Формирует и отправляет SystemEvent через зарегистрированный коллбек.
     */
    void FireEvent(AlertLevel level, const char* message, const char* details);

    // -----------------------------------------------------------------------
    // Состояние
    // -----------------------------------------------------------------------

    EventCallback               m_callback;     ///< Зарег. коллбек -> C#
    UsbPolicy                   m_policy;       ///< Политика текущей сессии
    std::atomic<bool>           m_running;      ///< Мониторинг активен?
    bool                        m_initialized;  ///< Initialize() прошёл успешно?

    // Message-Only Window
    HWND                        m_hwnd;         ///< Дескриптор невидимого окна
    HDEVNOTIFY                  m_hNotify;      ///< Дескриптор регистрации уведомлений
    std::thread                 m_pumpThread;   ///< Поток с Message Loop

    // Статистика устройств
    mutable std::mutex              m_devicesMutex;
    std::vector<UsbDeviceInfo>      m_devices;  ///< История всех подключённых устройств за сессию
};

#endif // __cplusplus

#endif // USB_MONITOR_H
