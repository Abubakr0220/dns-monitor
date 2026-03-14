/**
 * @file    dns_monitor.cpp
 * @brief   Реализация класса DnsMonitor — перехват и фильтрация DNS-запросов.
 *
 * ═══════════════════════════════════════════════════════════════════════════
 *  АРХИТЕКТУРА ПЕРЕХВАТА
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Перехватываются ТРИ функции системы Windows:
 *
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │ 1. DnsQuery_A  (dnsapi.dll)                                        │
 *   │    Высокоуровневый ANSI DNS API. Вызывают: Win32 приложения,       │
 *   │    старые браузеры, Python, Java (через JNI).                      │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │ 2. DnsQuery_W  (dnsapi.dll)                                        │
 *   │    Unicode-вариант. Вызывают: .NET приложения, PowerShell,         │
 *   │    системные службы Windows (svchost и т.д.).                      │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │ 3. getaddrinfo (ws2_32.dll)                                        │
 *   │    Winsock-резолвер стандарта POSIX. Вызывают: C/C++ приложения,  │
 *   │    Chrome, Firefox (используют свой резолвер через этот API),      │
 *   │    Node.js, го-приложения.                                         │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Механизм: MinHook (https://github.com/TsudaKageyu/minhook)
 *   MinHook в User-Mode пишет JMP-инструкцию (5 байт) в начало функции-жертвы,
 *   перенаправляя поток в наш Hook Stub. Оригинальный код сохраняется в
 *   "трамплине" (trampoline) — MinHook выделяет буфер и туда копирует
 *   перезаписанные инструкции + JMP обратно в тело оригинала.
 *
 *   Вызов:   app -> [hook_stub] -> (наша проверка) -> [trampoline] -> оригинал
 *   Блок:    app -> [hook_stub] -> (наша проверка) -> return ERROR_CODE
 *
 * ═══════════════════════════════════════════════════════════════════════════
 *  ИЗВЕСТНЫЕ ОГРАНИЧЕНИЯ (для документации)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  1. DNS over HTTPS (DoH): Chrome и Firefox с включённым DoH отправляют
 *     DNS через HTTPS (порт 443), минуя системные DNS-функции. Рекомендуется
 *     на уровне групповых политик или правил сетевого брандмауэра отключить DoH.
 *
 *  2. DNS кэш браузера: браузеры кэшируют DNS до 1 минуты самостоятельно.
 *     Поэтому помимо FlushSystemDnsCache() студенту нужно перезапустить браузер
 *     до начала сессии (или управляем перезапуском через сеть).
 *
 *  3. Прямые IP-подключения: обход через `curl 1.2.3.4` (без имени хоста)
 *     не будет перехвачен. Закрывается отдельным файрвольным правилом.
 *
 * ═══════════════════════════════════════════════════════════════════════════
 *  ЗАВИСИМОСТИ
 * ═══════════════════════════════════════════════════════════════════════════
 *  - third_party/minhook/include/MinHook.h
 *  - third_party/minhook/lib/MinHook.x64.lib (указывается в CMakeLists.txt)
 *  - Системные lib: dnsapi.lib, ws2_32.lib (указывается в CMakeLists.txt)
 */

// ── Стандартные заголовки ──────────────────────────────────────────────────
#define WIN32_LEAN_AND_MEAN  // Исключаем редко используемые части Windows.h
#define NOMINMAX             // Избегаем конфликта min/max макросов с std::
#include <Windows.h>
#include <windns.h>          // DNS_STATUS, DnsQuery_A/W, PDNS_RECORD
#include <ws2tcpip.h>        // getaddrinfo, ADDRINFOA, ADDRINFOW
#include <winsock2.h>        // WSAHOST_NOT_FOUND, WSA-коды ошибок
#include <strsafe.h>         // StringCbCopyA (безопасная strncpy)

// ── STL ───────────────────────────────────────────────────────────────────
#include <string>
#include <vector>
#include <unordered_set>
#include <map>
#include <mutex>
#include <atomic>
#include <sstream>
#include <algorithm>   // std::transform
#include <chrono>
#include <cctype>      // std::tolower, std::isdigit

// ── Наши заголовки ────────────────────────────────────────────────────────
#include "dns_monitor.h"
#include "third_party/minhook/include/MinHook.h"

// ── Линковка с системными библиотеками ────────────────────────────────────
// Прагмы дублируют CMakeLists.txt — на случай если кто-то включает файл в
// проект MSVC напрямую без CMake.
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "ws2_32.lib")


// =============================================================================
// РАЗДЕЛ 1: ГЛОБАЛЬНЫЕ ТРАМПЛИНЫ ДЛЯ MINHOOK
// =============================================================================
// MinHook требует, чтобы указатели на оригинальные функции (trampoline)
// передавались по АДРЕСУ при MH_CreateHookApi(). Они не могут быть внутри
// класса — нужны именно глобальные переменные (или статические члены класса).
// После MH_CreateHookApi MinHook записывает сюда указатель на трамплин —
// через него мы вызываем оригинальную функцию, избегая рекурсии.

// Трамплин для DnsQuery_A (dnsapi.dll)
static DnsMonitor::FnDnsQueryA    g_origDnsQueryA   = nullptr;

// Трамплин для DnsQuery_W (dnsapi.dll)
static DnsMonitor::FnDnsQueryW    g_origDnsQueryW   = nullptr;

// Трамплин для getaddrinfo (ws2_32.dll)
static DnsMonitor::FnGetAddrInfo  g_origGetAddrInfo = nullptr;


// =============================================================================
// РАЗДЕЛ 2: СТАТИЧЕСКИЕ HOOK STUB-ФУНКЦИИ
// =============================================================================
// Именно ЭТИ функции будут вставлены вместо системных через JMP-патч.
// Их сигнатуры ОБЯЗАНЫ совпадать с оригиналами (ABI, соглашение вызова).
// Стабы только перенаправляют вызов в экземпляр синглтона, вся логика — там.

// ─── Stub для DnsQuery_A ──────────────────────────────────────────────────
// Вызывается вместо оригинальной DnsQuery_A из dnsapi.dll.
// WINAPI = __stdcall — стандартное соглашение WinAPI функций x86/x64.
static DNS_STATUS WINAPI Hook_DnsQueryA(
    PCSTR       pszName,          // Имя запрашиваемого хоста (ANSI, null-terminated)
    WORD        wType,            // Тип DNS-записи: DNS_TYPE_A (1), AAAA (28) и т.д.
    DWORD       Options,          // Флаги: DNS_QUERY_STANDARD и т.д.
    PVOID       pExtra,           // Зарезервировано / серверные подсказки
    PDNS_RECORD* ppQueryResults,  // [OUT] Результат — связный список DNS-записей
    PVOID*      pReserved)        // Зарезервировано (всегда NULL)
{
    // Делегируем в MetodInstance, которая выполняет всю логику
    return DnsMonitor::GetInstance().OnDnsQueryA(
        pszName, wType, Options, pExtra, ppQueryResults, pReserved);
}

// ─── Stub для DnsQuery_W ──────────────────────────────────────────────────
// Unicode-версия. .NET, PowerShell и системные компоненты обычно вызывают эту.
// Мы конвертируем PCWSTR -> std::string для единой логики проверки.
static DNS_STATUS WINAPI Hook_DnsQueryW(
    PCWSTR      pszName,          // Имя хоста в Unicode
    WORD        wType,
    DWORD       Options,
    PVOID       pExtra,
    PDNS_RECORD* ppQueryResults,
    PVOID*      pReserved)
{
    return DnsMonitor::GetInstance().OnDnsQueryW(
        pszName, wType, Options, pExtra, ppQueryResults, pReserved);
}

// ─── Stub для getaddrinfo ─────────────────────────────────────────────────
// Winsock-резолвер. Chrome, Firefox, Node.js, Go — через этот вызов.
// WSAAPI = __cdecl (на x64 однако ABI одинаков, но важно для x86-совместимости)
static int WSAAPI Hook_GetAddrInfo(
    PCSTR               pNodeName,    // Имя хоста (ANSI) или IPv4/IPv6 строка
    PCSTR               pServiceName, // Порт/сервис ("80", "http") — может быть NULL
    const ADDRINFOA*    pHints,       // Подсказки по типу адреса — может быть NULL
    PADDRINFOA*         ppResult)     // [OUT] Результат — связный список адресов
{
    return DnsMonitor::GetInstance().OnGetAddrInfo(
        pNodeName, pServiceName, pHints, ppResult);
}


// =============================================================================
// РАЗДЕЛ 3: ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (файловый scope, не в классе)
// =============================================================================

// Возвращает текущее время как Unix timestamp (секунды с 01.01.1970 UTC)
static int64_t NowUnix()
{
    return static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

// Конвертирует PCWSTR (wide string) в std::string (UTF-8 совместимый ANSI)
// для единой обработки Unicode и ANSI DNS-запросов.
static std::string WideToNarrow(PCWSTR wide)
{
    if (wide == nullptr) return {};
    // Определяем нужный размер буфера
    int needed = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string result(static_cast<size_t>(needed - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, &result[0], needed, nullptr, nullptr);
    return result;
}


// =============================================================================
// РАЗДЕЛ 4: РЕАЛИЗАЦИЯ СИНГЛТОНА
// =============================================================================

DnsMonitor& DnsMonitor::GetInstance()
{
    // Статическая локальная переменная — инициализируется ровно один раз,
    // thread-safe начиная с C++11 (гарантирует стандарт).
    static DnsMonitor instance;
    return instance;
}

DnsMonitor::DnsMonitor()
    : m_callback(nullptr)
    , m_running(false)
    , m_initialized(false)
    , m_origDnsQueryA(nullptr)
    , m_origDnsQueryW(nullptr)
    , m_origGetAddrInfo(nullptr)
{}

DnsMonitor::~DnsMonitor()
{
    // Защитный Stop на случай аварийного завершения без явного вызова StopSession
    if (m_running.load()) {
        Stop();
    }
    if (m_initialized) {
        MH_Uninitialize();
    }
}


// =============================================================================
// РАЗДЕЛ 5: ЖИЗНЕННЫЙ ЦИКЛ
// =============================================================================

// ─── Initialize ──────────────────────────────────────────────────────────────
bool DnsMonitor::Initialize(EventCallback callback)
{
    if (m_initialized) return true; // Идемпотентно — безопасно вызывать повторно

    if (callback == nullptr) return false;
    m_callback = callback;

    // ── Инициализируем движок MinHook ──────────────────────────────────────
    // MH_Initialize() готовит внутренние структуры MinHook (пул трамплинов,
    // мьютекс доступа к патченным страницам). Вызывается ОДИН РАЗ.
    MH_STATUS mhStatus = MH_Initialize();

    if (mhStatus != MH_OK && mhStatus != MH_ERROR_ALREADY_INITIALIZED) {
        // MH_ERROR_ALREADY_INITIALIZED — не ошибка (e.g. если Initialize вызван
        // дважды из-за логической ошибки клиентского кода)
        return false;
    }

    m_initialized = true;
    return true;
}


// ─── Start ────────────────────────────────────────────────────────────────────
bool DnsMonitor::Start(const std::vector<std::string>& whitelist)
{
    if (!m_initialized) return false;
    if (m_running.load()) return true; // Сессия уже запущена — не двойной старт

    // ── Шаг 1: Применяем белый список ─────────────────────────────────────
    {
        m_exactDomains.clear();
        m_wildcards.clear();
        m_stats.clear();

        for (const auto& entry : whitelist) {
            if (entry.size() > 2 && entry[0] == '*' && entry[1] == '.') {
                // Wildcard "*.example.com" -> сохраняем суффикс ".example.com"
                // Это позволяет быстро проверять через domain.ends_with(suffix)
                m_wildcards.push_back(entry.substr(1)); // ".example.com"
            } else {
                // Точный домен — добавляем в хэш-сет O(1) поиска
                m_exactDomains.insert(entry);
            }
        }
    }

    // ── Шаг 2: Сброс DNS кэша ─────────────────────────────────────────────
    // Это критично: студент мог посещать запрещённые сайты до начала сессии.
    // Их DNS-записи сидят в кэше Windows и браузера — запрос пройдёт без
    // системного вызова DnsQuery/getaddrinfo, минуя наши хуки.
    FlushSystemDnsCache();

    // ── Шаг 3: Установка хука на DnsQuery_A ───────────────────────────────
    //
    //   MH_CreateHookApi(имя_DLL, имя_функции, наш_stub, &трамплин)
    //
    //   - "dnsapi.dll"    — целевая DLL (MinHook ищет её в адресном пространстве процесса)
    //   - "DnsQuery_A"    — экспортируемое имя функции (точное, регистрозависимое)
    //   - Hook_DnsQueryA  — наш stub, куда перенаправляется выполнение
    //   - &g_origDnsQueryA — MinHook запишет сюда адрес трамплина (копии оригинала)
    //
    // После этого вызова хук СОЗДАН, но ещё НЕ АКТИВЕН. Активация — MH_EnableHook().
    {
        MH_STATUS s = MH_CreateHookApi(
            L"dnsapi.dll",              // [in]  Имя целевой DLL
            "DnsQuery_A",               // [in]  Имя экспорта (ANSI-строка)
            reinterpret_cast<LPVOID>(&Hook_DnsQueryA),          // [in]  Адрес нашего stub
            reinterpret_cast<LPVOID*>(&g_origDnsQueryA)         // [out] Адрес трамплина
        );

        // MH_ERROR_ALREADY_CREATED — хук уже существует, это нормально при повторном Start
        if (s != MH_OK && s != MH_ERROR_ALREADY_CREATED) {
            // Логируем ошибку но не падаем — getaddrinfo хук всё равно поставим
            FireEvent(ALERT_WARNING,
                      "DNS Monitor: не удалось установить хук DnsQuery_A",
                      "{\"minhook_status\": " + std::to_string(static_cast<int>(s)) + "}");
        } else {
            // Сохраняем трамплин в член класса для единого доступа из OnDnsQueryA
            m_origDnsQueryA = g_origDnsQueryA;
        }
    }

    // ── Шаг 4: Установка хука на DnsQuery_W ───────────────────────────────
    // Unicode-версия. Логика идентична — только DLL та же (dnsapi.dll),
    // имя функции "DnsQuery_W", stub — Hook_DnsQueryW.
    {
        MH_STATUS s = MH_CreateHookApi(
            L"dnsapi.dll",
            "DnsQuery_W",
            reinterpret_cast<LPVOID>(&Hook_DnsQueryW),
            reinterpret_cast<LPVOID*>(&g_origDnsQueryW)
        );

        if (s != MH_OK && s != MH_ERROR_ALREADY_CREATED) {
            FireEvent(ALERT_WARNING,
                      "DNS Monitor: не удалось установить хук DnsQuery_W",
                      "{\"minhook_status\": " + std::to_string(static_cast<int>(s)) + "}");
        } else {
            m_origDnsQueryW = g_origDnsQueryW;
        }
    }

    // ── Шаг 5: Установка хука на getaddrinfo (ws2_32.dll) ─────────────────
    // Это самый важный хук: через него идут Chrome, Firefox, Node.js, Python.
    // Без него студент может зайти на любой сайт через браузер.
    {
        MH_STATUS s = MH_CreateHookApi(
            L"ws2_32.dll",                                       // Winsock 2
            "getaddrinfo",                                        // POSIX-резолвер
            reinterpret_cast<LPVOID>(&Hook_GetAddrInfo),
            reinterpret_cast<LPVOID*>(&g_origGetAddrInfo)
        );

        if (s != MH_OK && s != MH_ERROR_ALREADY_CREATED) {
            // Без этого хука DNS-фильтрация крайне ненадёжна — это критическая ошибка
            FireEvent(ALERT_CRITICAL,
                      "DNS Monitor: КРИТИЧНО — не удалось установить хук getaddrinfo!",
                      "{\"minhook_status\": " + std::to_string(static_cast<int>(s)) + "}");
            return false;
        }
        m_origGetAddrInfo = g_origGetAddrInfo;
    }

    // ── Шаг 6: Активация ВСЕХ созданных хуков ─────────────────────────────
    // MH_EnableHook(MH_ALL_HOOKS) атомарно включает все созданные хуки.
    // После этого вызова JMP-патчи записаны в код системных DLL и
    // любой вызов DnsQuery_A/W или getaddrinfo пойдёт через наши stubs.
    //
    // ВАЖНО: MH_EnableHook защищён внутренним мьютексом MinHook —
    // потокобезопасен относительно других вызовов MH_* функций.
    MH_EnableHook(MH_ALL_HOOKS);

    // Переключаем флаг — теперь хуки будут фильтровать запросы
    m_running.store(true);

    // Информируем преподавателя о старте сессии
    {
        std::string details = "{\"event\":\"session_start\","
                              "\"whitelist_size\":" + std::to_string(whitelist.size()) + ","
                              "\"exact_domains\":" + std::to_string(m_exactDomains.size()) + ","
                              "\"wildcard_rules\":" + std::to_string(m_wildcards.size()) + "}";
        FireEvent(ALERT_INFO, "DNS Monitor: сессия запущена", details.c_str());
    }

    return true;
}


// ─── Stop ─────────────────────────────────────────────────────────────────────
void DnsMonitor::Stop()
{
    if (!m_running.load()) return;

    // Сначала снимаем флаг — чтобы перехватчики перестали фильтровать
    // (новые звонки DnsQuery пройдут напрямую в оригинал через трамплин)
    m_running.store(false);

    // ── Деактивация хуков ─────────────────────────────────────────────────
    // MH_DisableHook(MH_ALL_HOOKS) убирает JMP-патчи из кода системных DLL,
    // восстанавливая оригинальные байты. После этого DnsQuery/getaddrinfo
    // работают штатно без нашей логики.
    // Хуки можно снова включить через MH_EnableHook при следующем Start().
    MH_DisableHook(MH_ALL_HOOKS);

    FireEvent(ALERT_INFO, "DNS Monitor: сессия остановлена",
              "{\"event\":\"session_stop\"}");
}


// ─── Uninitialize ─────────────────────────────────────────────────────────────
void DnsMonitor::Uninitialize()
{
    if (m_running.load()) Stop();
    if (!m_initialized)   return;

    // Удаляем все хуки и освобождаем внутренние ресурсы MinHook (trampoline pool)
    MH_RemoveHook(MH_ALL_HOOKS);
    MH_Uninitialize();

    m_initialized       = false;
    m_callback          = nullptr;
    m_origDnsQueryA     = nullptr;
    m_origDnsQueryW     = nullptr;
    m_origGetAddrInfo   = nullptr;
}


// =============================================================================
// РАЗДЕЛ 6: ЛОГИКА ПЕРЕХВАТЧИКОВ (вызываются из hook stubs)
// =============================================================================

// ─── OnDnsQueryA ─────────────────────────────────────────────────────────────
DNS_STATUS DnsMonitor::OnDnsQueryA(
    PCSTR pszName, WORD wType, DWORD Options,
    PVOID pExtra, PDNS_RECORD* ppQueryResults, PVOID* pReserved)
{
    // Если сессия не активна или трамплин не установлен — пропускаем без изменений
    if (!m_running.load() || m_origDnsQueryA == nullptr) {
        // Аварийный путь: хук активен, но сессия уже остановлена
        // Такое может произойти в момент гонки Stop() vs. системного вызова
        if (m_origDnsQueryA) {
            return m_origDnsQueryA(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
        }
        return DNS_ERROR_RCODE_SERVER_FAILURE; // Безопасный fallback
    }

    // NULL имя — некорректный вызов, не трогаем
    if (pszName == nullptr) {
        return m_origDnsQueryA(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
    }

    const std::string domain = NormalizeDomain(pszName);

    if (IsDomainAllowed(domain)) {
        // ✓ Домен в белом списке — вызываем оригинальную функцию через трамплин
        return m_origDnsQueryA(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
    }

    // ✗ Домен НЕ в белом списке — записываем инцидент и блокируем
    RecordIncident(domain);

    std::string msg     = "Заблокирован DNS-запрос (DnsQuery_A): " + domain;
    std::string details = BuildBlockDetails(domain, "DnsQuery_A");
    FireEvent(ALERT_CRITICAL, msg.c_str(), details.c_str());

    // Возвращаем DNS_ERROR_RCODE_NAME_ERROR (9003 = NXDOMAIN):
    // Означает "домен не существует" — безобидная ошибка с точки зрения браузера
    // (не вызывает повторных попыток, в отличие от SERVFAIL)
    return DNS_ERROR_RCODE_NAME_ERROR;
}


// ─── OnDnsQueryW ─────────────────────────────────────────────────────────────
DNS_STATUS DnsMonitor::OnDnsQueryW(
    PCWSTR pszName, WORD wType, DWORD Options,
    PVOID pExtra, PDNS_RECORD* ppQueryResults, PVOID* pReserved)
{
    if (!m_running.load() || m_origDnsQueryW == nullptr) {
        if (m_origDnsQueryW) {
            return m_origDnsQueryW(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
        }
        return DNS_ERROR_RCODE_SERVER_FAILURE;
    }

    if (pszName == nullptr) {
        return m_origDnsQueryW(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
    }

    // Конвертируем Unicode -> ANSI для единой логики проверки
    const std::string domain = NormalizeDomain(WideToNarrow(pszName).c_str());

    if (IsDomainAllowed(domain)) {
        return m_origDnsQueryW(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
    }

    RecordIncident(domain);

    std::string msg     = "Заблокирован DNS-запрос (DnsQuery_W): " + domain;
    std::string details = BuildBlockDetails(domain, "DnsQuery_W");
    FireEvent(ALERT_CRITICAL, msg.c_str(), details.c_str());

    return DNS_ERROR_RCODE_NAME_ERROR;
}


// ─── OnGetAddrInfo ────────────────────────────────────────────────────────────
int DnsMonitor::OnGetAddrInfo(
    PCSTR pNodeName, PCSTR pServiceName,
    const ADDRINFOA* pHints, PADDRINFOA* ppResult)
{
    if (!m_running.load() || m_origGetAddrInfo == nullptr) {
        if (m_origGetAddrInfo) {
            return m_origGetAddrInfo(pNodeName, pServiceName, pHints, ppResult);
        }
        return WSAHOST_NOT_FOUND;
    }

    // Пустое имя — исключаем из проверки (локальные запросы)
    if (pNodeName == nullptr || pNodeName[0] == '\0') {
        return m_origGetAddrInfo(pNodeName, pServiceName, pHints, ppResult);
    }

    const std::string domain = NormalizeDomain(pNodeName);

    // Пропускаем числовые IP-адреса: "192.168.1.1", "::1" и т.д.
    // Они не являются DNS-именами — блокировать их здесь бессмысленно.
    // Признак числового адреса: первый символ — цифра или ':'
    if (std::isdigit(static_cast<unsigned char>(domain[0])) || domain[0] == ':') {
        return m_origGetAddrInfo(pNodeName, pServiceName, pHints, ppResult);
    }

    if (IsDomainAllowed(domain)) {
        return m_origGetAddrInfo(pNodeName, pServiceName, pHints, ppResult);
    }

    RecordIncident(domain);

    std::string msg     = "Заблокирован DNS-запрос (getaddrinfo): " + domain;
    std::string details = BuildBlockDetails(domain, "getaddrinfo");
    FireEvent(ALERT_CRITICAL, msg.c_str(), details.c_str());

    // WSAHOST_NOT_FOUND (11001) — стандартная Winsock ошибка "хост не найден"
    // Браузер покажет "ERR_NAME_NOT_RESOLVED" — именно то что нам нужно
    return WSAHOST_NOT_FOUND;
}


// =============================================================================
// РАЗДЕЛ 7: ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ КЛАССА
// =============================================================================

// ─── IsDomainAllowed ──────────────────────────────────────────────────────────
bool DnsMonitor::IsDomainAllowed(const std::string& domain) const
{
    // Быстрая проверка — точное вхождение в хэш-сет: O(1) average
    if (m_exactDomains.count(domain)) return true;

    // Проверка wildcard-масок: "*.example.com" хранится как ".example.com"
    // Домен разрешён если:
    //   a) Он является поддоменом: "sub.example.com".ends_with(".example.com") -> true
    //   b) Он совпадает с базовым доменом: "example.com" == "example.com"
    for (const auto& suffix : m_wildcards) {
        // suffix = ".example.com"

        if (domain.size() > suffix.size()) {
            // Проверяем поддомен: "sub.example.com" заканчивается на ".example.com"
            if (domain.compare(
                    domain.size() - suffix.size(),  // позиция начала суффикса
                    suffix.size(),                  // длина суффикса
                    suffix                          // сам суффикс
                ) == 0)
            {
                return true;
            }
        }

        // Проверяем базовый домен: "example.com" == suffix.substr(1) == "example.com"
        if (domain == suffix.substr(1)) return true;
    }

    return false;
}


// ─── NormalizeDomain ─────────────────────────────────────────────────────────
/*static*/ std::string DnsMonitor::NormalizeDomain(const char* raw)
{
    if (raw == nullptr || raw[0] == '\0') return {};

    std::string result(raw);

    // Приводим к нижнему регистру: "GOOGLE.COM" -> "google.com"
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    // Убираем конечную точку FQDN: "google.com." -> "google.com"
    if (!result.empty() && result.back() == '.') {
        result.pop_back();
    }

    return result;
}


// ─── RecordIncident ───────────────────────────────────────────────────────────
// Записывает факт блокировки в статистику (thread-safe).
void DnsMonitor::RecordIncident(const std::string& domain)
{
    std::lock_guard<std::mutex> lock(m_statsMutex);
    auto& rec = m_stats[domain];
    if (rec.attempts == 0) {
        rec.firstSeen = NowUnix(); // Записываем время первой попытки
    }
    ++rec.attempts;
}


// ─── BuildBlockDetails ────────────────────────────────────────────────────────
// Формирует JSON-строку с деталями для поля details в SystemEvent.
std::string DnsMonitor::BuildBlockDetails(const std::string& domain, const char* method) const
{
    // Читаем счётчик из статистики (уже обновлён в RecordIncident)
    int attempts = 0;
    {
        std::lock_guard<std::mutex> lock(m_statsMutex);
        auto it = m_stats.find(domain);
        if (it != m_stats.end()) attempts = it->second.attempts;
    }

    return std::string("{\"domain\":\"") + domain
        + "\",\"method\":\"" + method
        + "\",\"attempts\":" + std::to_string(attempts) + "}";
}


// ─── FireEvent ────────────────────────────────────────────────────────────────
void DnsMonitor::FireEvent(AlertLevel level, const char* message, const char* details)
{
    if (m_callback == nullptr) return;

    SystemEvent ev{};               // Нулевая инициализация всей структуры
    ev.module    = MODULE_DNS;
    ev.level     = level;
    ev.timestamp = NowUnix();

    // StringCbCopyA — безопасная копия с гарантией нуль-терминатора
    StringCbCopyA(ev.message, sizeof(ev.message), message ? message : "");
    StringCbCopyA(ev.details, sizeof(ev.details), details ? details : "{}");

    // Коллбек вызывается из потока, который запросил DNS-резолвинг
    // (например, из сетевого потока Chrome). C# обёртка должна использовать BeginInvoke.
    m_callback(&ev);
}


// ─── FlushSystemDnsCache ──────────────────────────────────────────────────────
/*static*/ void DnsMonitor::FlushSystemDnsCache()
{
    // ── Способ 1: Официальный API (DnsFlushResolverCache) ─────────────────
    // Функция экспортируется из dnsapi.dll но НЕ объявлена в публичных SDK
    // заголовках — получаем её через GetProcAddress.
    // Соответствует команде "ipconfig /flushdns".
    {
        HMODULE hDnsApi = GetModuleHandleW(L"dnsapi.dll");
        if (hDnsApi == nullptr) {
            // dnsapi.dll могла ещё не быть загружена — принудительно грузим
            hDnsApi = LoadLibraryW(L"dnsapi.dll");
        }

        if (hDnsApi != nullptr) {
            // Объявляем тип функции (она не принимает аргументов, возвращает BOOL)
            typedef BOOL (WINAPI* PFnDnsFlushResolverCache)(void);
            PFnDnsFlushResolverCache pfnFlush =
                reinterpret_cast<PFnDnsFlushResolverCache>(
                    GetProcAddress(hDnsApi, "DnsFlushResolverCache"));

            if (pfnFlush != nullptr) {
                pfnFlush(); // Сбрасываем кэш через официальный API
                return;     // Успех — выходим
            }
        }
    }

    // ── Способ 2: Перезапуск службы DNS Client (резервный) ────────────────
    // Если DnsFlushResolverCache недоступна (редкая ситуация), перезапускаем
    // системную службу DNS Client (dnscache). Требует прав Enterprise Admin.
    // Этот путь medikam не должен срабатывать на нормальных системах.
    {
        SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (hSCM != nullptr) {
            SC_HANDLE hSvc = OpenServiceW(hSCM, L"dnscache",
                                          SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS);
            if (hSvc != nullptr) {
                SERVICE_STATUS ss{};
                ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
                Sleep(500); // Даём службе завершиться
                StartServiceW(hSvc, 0, nullptr);
                CloseServiceHandle(hSvc);
            }
            CloseServiceHandle(hSCM);
        }
    }
}


// =============================================================================
// РАЗДЕЛ 8: ОТЧЁТНОСТЬ И ТЕСТИРОВАНИЕ
// =============================================================================

// ─── GetReport ────────────────────────────────────────────────────────────────
void DnsMonitor::GetReport(std::string& out) const
{
    std::lock_guard<std::mutex> lock(m_statsMutex);

    std::ostringstream oss;
    oss << "{\n"
        << "  \"module\": \"DNS\",\n"
        << "  \"blocked_count\": " << m_stats.size() << ",\n"
        << "  \"incidents\": [\n";

    bool first = true;
    for (const auto& [domain, rec] : m_stats) {
        if (!first) oss << ",\n";
        first = false;
        oss << "    {"
            << "\"domain\": \"" << domain << "\""
            << ", \"attempts\": "   << rec.attempts
            << ", \"first_seen\": " << rec.firstSeen
            << "}";
    }

    oss << "\n  ]\n}";
    out = oss.str();
}


// ─── SendTestEvent ────────────────────────────────────────────────────────────
// Вызывается для тестирования GUI без реальной DLL-логики.
void DnsMonitor::SendTestEvent()
{
    FireEvent(ALERT_CRITICAL,
              "Заблокирован DNS-запрос (DnsQuery_A): vk.com",
              R"({"domain":"vk.com","method":"TEST_STUB","attempts":1})");
}
