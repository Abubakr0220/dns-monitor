/**
 * @file    dns_monitor.h
 * @brief   Объявление класса DnsMonitor — модуля перехвата и контроля DNS-запросов.
 *
 * Механизм перехвата: API Hooking функций DnsQuery_A / DnsQuery_W / getaddrinfo через MinHook.
 * Выбранный подход позволяет работать в User-Mode без драйверов ядра.
 *
 * @note    Перед использованием необходимы права Администратора.
 *          Класс является синглтоном, так как MinHook патчит глобальные
 *          системные функции и не может быть инициализирован дважды.
 */

#pragma once

#ifndef DNS_MONITOR_H
#define DNS_MONITOR_H

#include "monitoring_api.h"

// Заголовки только для C++ компилятора (не для C#)
#ifdef __cplusplus

#include <Windows.h>
#include <windns.h>       // DNS_STATUS, DnsQuery_A и т.д.
#include <ws2tcpip.h>     // getaddrinfo, ADDRINFOA
#include <string>
#include <unordered_set>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>

/**
 * @class DnsMonitor
 * @brief Перехватывает DNS-запросы, проверяет домены по белому списку и 
 *        блокирует запрещённые. Отправляет события через зарегистрированный коллбек.
 *
 * Жизненный цикл:
 *   DnsMonitor::GetInstance() -> Initialize(callback) -> Start(config) -> ... -> Stop() -> Uninitialize()
 */
class DnsMonitor {
public:
    // -----------------------------------------------------------------------
    // Синглтон
    // -----------------------------------------------------------------------
    
    /// @brief Получить единственный экземпляр класса
    static DnsMonitor& GetInstance();

    // Запрет копирования
    DnsMonitor(const DnsMonitor&) = delete;
    DnsMonitor& operator=(const DnsMonitor&) = delete;

    // -----------------------------------------------------------------------
    // Управление жизненным циклом
    // -----------------------------------------------------------------------

    /**
     * @brief  Инициализирует MinHook и регистрирует коллбек.
     *         Не устанавливает хуки — только готовит инфраструктуру.
     *
     * @param  callback  Функция для получения событий. Коллбек будет вызываться
     *                   из рабочего потока — C# обёртка должна использовать Invoke/BeginInvoke.
     * @return true при успехе
     */
    bool Initialize(EventCallback callback);

    /**
     * @brief  Запускает сессию мониторинга:
     *         1. Очищает DNS-кэш (ipconfig /flushdns)
     *         2. Применяет белый список
     *         3. Устанавливает хуки на DnsQuery_A и getaddrinfo
     *
     * @param  whitelist       Вектор строк с разрешёнными доменами/масками
     *                         Примеры: "google.com", "*.microsoft.com"
     */
    bool Start(const std::vector<std::string>& whitelist);

    /**
     * @brief  Снимает хуки, сбрасывает активную сессию.
     *         Накопленная статистика остаётся и может быть прочитана через GetReport().
     */
    void Stop();

    /**
     * @brief  Выгружает MinHook полностью. Должна быть вызвана при Shutdown.
     */
    void Uninitialize();

    // -----------------------------------------------------------------------
    // Отчётность
    // -----------------------------------------------------------------------

    /**
     * @brief  Формирует JSON-строку с итогами сессии.
     *
     * Формат JSON:
     * @code
     * {
     *   "module": "DNS",
     *   "blocked_count": 5,
     *   "incidents": [
     *     { "domain": "vk.com", "attempts": 3, "first_seen": 1710000000 },
     *     { "domain": "telegram.org", "attempts": 2, "first_seen": 1710000050 }
     *   ]
     * }
     * @endcode
     *
     * @param  out  Строка, в которую будет записан JSON
     */
    void GetReport(std::string& out) const;

    /**
     * @brief   Отправляет фейковое событие блокировки для тестирования GUI.
     *          Вызывается без активной сессии (для демонстрации коллеге).
     */
    void SendTestEvent();

    // -----------------------------------------------------------------------
    // Хуки (вызываются ТОЛЬКО из статических функций-перехватчиков)
    // -----------------------------------------------------------------------
    
    /**
     * @brief  Внутренняя логика перехвата после вызова DnsQuery_A (ANSI).
     * @return Исходный результат DnsQuery или DNS_ERROR_RCODE_NAME_ERROR при блокировке.
     */
    DNS_STATUS OnDnsQueryA(PCSTR pszName, WORD wType, DWORD Options,
                           PVOID pExtra, PDNS_RECORD* ppQueryResults,
                           PVOID* pReserved);

    /**
     * @brief  Внутренняя логика перехвата после вызова DnsQuery_W (Unicode).
     *         Unicode-версия для .NET, PowerShell, системных компонентов.
     */
    DNS_STATUS OnDnsQueryW(PCWSTR pszName, WORD wType, DWORD Options,
                           PVOID pExtra, PDNS_RECORD* ppQueryResults,
                           PVOID* pReserved);

    /**
     * @brief  Внутренняя логика перехвата после вызова getaddrinfo.
     * @return 0 (успех) или WSAHOST_NOT_FOUND при блокировке.
     */
    int OnGetAddrInfo(PCSTR pNodeName, PCSTR pServiceName,
                      const ADDRINFOA* pHints, PADDRINFOA* ppResult);

private:
    // Конструктор/деструктор приватны (синглтон)
    DnsMonitor();
    ~DnsMonitor();

    // -----------------------------------------------------------------------
    // Вспомогательные методы
    // -----------------------------------------------------------------------

    /**
     * @brief  Проверяет, разрешён ли домен по белому списку.
     *         Поддерживает точное совпадение и wildcard-маску (*.example.com).
     *
     * @param  domain  Строчный домен для проверки (уже нормализованный)
     * @return true — разрешён, false — запрещён
     */
    bool IsDomainAllowed(const std::string& domain) const;

    /**
     * @brief  Нормализует доменное имя: приводит к нижнему регистру,
     *         убирает конечную точку.
     */
    static std::string NormalizeDomain(const char* raw);

    /**
     * @brief  Формирует и отправляет SystemEvent через зарегистрированный коллбек.
     */
    void FireEvent(AlertLevel level, const char* message, const char* details);

    /**
     * @brief  Потокобезопасная запись инцидента блокировки в статистику.
     */
    void RecordIncident(const std::string& domain);

    /**
     * @brief  Формирует JSON-строку с деталями для поля details в SystemEvent.
     */
    std::string BuildBlockDetails(const std::string& domain, const char* method) const;

    /**
     * @brief  Программно сбрасывает системный DNS-кэш (аналог ipconfig /flushdns).
     */
    static void FlushSystemDnsCache();

    // -----------------------------------------------------------------------
    // Состояние и данные
    // -----------------------------------------------------------------------

    EventCallback                           m_callback;     ///< Зарег. коллбек -> C#
    std::atomic<bool>                       m_running;      ///< Сессия активна?
    bool                                    m_initialized;  ///< MinHook инициализирован?
    
    // Белый список (thread-safe чтение, запись только в Start())
    std::unordered_set<std::string>         m_exactDomains; ///< Точные совпадения
    std::vector<std::string>                m_wildcards;    ///< Маски (*.example.com)
    
    // Статистика инцидентов
    mutable std::mutex                      m_statsMutex;
    struct IncidentRecord {
        int       attempts;
        int64_t   firstSeen;
    };
    std::map<std::string, IncidentRecord>   m_stats;        ///< domain -> {счётчик, время}

    // -----------------------------------------------------------------------
    // Указатели на оригинальные (unhook) версии системных функций
    // -----------------------------------------------------------------------
    
    typedef DNS_STATUS (WINAPI *FnDnsQueryA)(
        PCSTR pszName, WORD wType, DWORD Options,
        PVOID pExtra, PDNS_RECORD* ppQueryResults, PVOID* pReserved);

    typedef DNS_STATUS (WINAPI *FnDnsQueryW)(
        PCWSTR pszName, WORD wType, DWORD Options,
        PVOID pExtra, PDNS_RECORD* ppQueryResults, PVOID* pReserved);

    typedef int (WSAAPI *FnGetAddrInfo)(
        PCSTR pNodeName, PCSTR pServiceName,
        const ADDRINFOA* pHints, PADDRINFOA* ppResult);

    FnDnsQueryA   m_origDnsQueryA;   ///< Трамплин MinHook для DnsQuery_A
    FnDnsQueryW   m_origDnsQueryW;   ///< Трамплин MinHook для DnsQuery_W
    FnGetAddrInfo m_origGetAddrInfo; ///< Трамплин MinHook для getaddrinfo
};

#endif // __cplusplus

#endif // DNS_MONITOR_H
