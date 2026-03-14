/**
 * @file    usb_monitor.cpp
 * @brief   Реализация класса UsbMonitor.
 *
 * Механизм обнаружения:
 *   Невидимое (Message-Only) окно, работающее в отдельном потоке,
 *   регистрирует уведомления через RegisterDeviceNotification с GUID тома
 *   и слушает WM_DEVICECHANGE.
 *
 * Политики (UsbPolicy):
 *   - ALLOWED:   Флешка монтируется штатно. Отправляется INFO-алерт.
 *   - READ_ONLY: Флешка монтируется только для чтения через ключ реестра WriteProtect.
 *   - BLOCKED:   Флешка программно извлекается (DeviceIoControl FSCTL_DISMOUNT_VOLUME
 *                + CM_Request_Device_EjectW). Отправляется WARNING-алерт.
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "usb_monitor.h"

#include <Windows.h>
#include <dbt.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <winioctl.h>   // FSCTL_DISMOUNT_VOLUME, IOCTL_STORAGE_EJECT_MEDIA
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstring>

#pragma comment(lib, "setupapi.lib")

// -----------------------------------------------------------------------
// Вспомогательная функция — GUID тома (для RegisterDeviceNotification)
// -----------------------------------------------------------------------

// GUID_DEVINTERFACE_VOLUME — официальный идентификатор класса томов дисков
// {53F5630D-B6BF-11D0-94F2-00A0C91EFB8B}
static const GUID GUID_DEVINTERFACE_VOLUME_GUID = {
    0x53F5630D, 0xB6BF, 0x11D0,
    { 0x94, 0xF2, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x8B }
};

// -----------------------------------------------------------------------
// Вспомогательная функция — текущий Unix timestamp
// -----------------------------------------------------------------------
static int64_t NowUnix() {
    return static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

// -----------------------------------------------------------------------
// Синглтон
// -----------------------------------------------------------------------

UsbMonitor& UsbMonitor::GetInstance() {
    static UsbMonitor instance;
    return instance;
}

UsbMonitor::UsbMonitor()
    : m_callback(nullptr)
    , m_policy(USB_POLICY_ALLOWED)
    , m_running(false)
    , m_initialized(false)
    , m_hwnd(nullptr)
    , m_hNotify(nullptr)
{}

UsbMonitor::~UsbMonitor() {
    if (m_running.load()) {
        Stop();
    }
}

// -----------------------------------------------------------------------
// Initialize / Uninitialize
// -----------------------------------------------------------------------

bool UsbMonitor::Initialize(EventCallback callback) {
    if (m_initialized) return true;
    if (callback == nullptr) return false;
    m_callback = callback;
    m_initialized = true;
    return true;
}

void UsbMonitor::Uninitialize() {
    if (m_running.load()) Stop();
    m_callback = nullptr;
    m_initialized = false;
}

// -----------------------------------------------------------------------
// Start
// -----------------------------------------------------------------------

bool UsbMonitor::Start(UsbPolicy policy) {
    if (!m_initialized || m_running.load()) return false;

    m_policy = policy;
    m_devices.clear();
    m_running.store(true);

    // Запускаем Message Pump в отдельном потоке
    m_pumpThread = std::thread([this]() {
        this->MessagePumpThread();
    });

    return true;
}

// -----------------------------------------------------------------------
// Stop
// -----------------------------------------------------------------------

void UsbMonitor::Stop() {
    if (!m_running.load()) return;
    m_running.store(false);

    // Посылаем WM_QUIT в Message Loop нашего потока, чтобы он завершился
    if (m_hwnd != nullptr) {
        PostMessage(m_hwnd, WM_QUIT, 0, 0);
    }

    if (m_pumpThread.joinable()) {
        m_pumpThread.join();
    }
}

// -----------------------------------------------------------------------
// MessagePumpThread — тело рабочего потока
// -----------------------------------------------------------------------

void UsbMonitor::MessagePumpThread() {
    // 1. Регистрируем класс окна (уникальное имя во избежание конфликтов)
    const wchar_t CLASS_NAME[] = L"MonitoringCore_UsbMonitorMsgWnd";

    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc   = UsbMonitor::StaticWndProc;
    wc.hInstance     = GetModuleHandleW(nullptr);
    wc.lpszClassName = CLASS_NAME;
    RegisterClassExW(&wc); // Может вернуть 0 если уже зарегистрирован — это нормально

    // 2. Создаём Message-Only окно (HWND_MESSAGE = не показывается на экране)
    m_hwnd = CreateWindowExW(
        0, CLASS_NAME, L"UsbMonitor",
        0, 0, 0, 0, 0,
        HWND_MESSAGE,   // Родитель — специальный псевдодескриптор
        nullptr, GetModuleHandleW(nullptr), this // this передаём в CREATESTRUCT
    );

    if (m_hwnd == nullptr) {
        m_running.store(false);
        return;
    }

    // 3. Регистрируем уведомления о подключении/отключении томов
    DEV_BROADCAST_DEVICEINTERFACE_W notifyFilter = {};
    notifyFilter.dbcc_size       = sizeof(DEV_BROADCAST_DEVICEINTERFACE_W);
    notifyFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    notifyFilter.dbcc_classguid  = GUID_DEVINTERFACE_VOLUME_GUID;

    m_hNotify = RegisterDeviceNotificationW(
        m_hwnd,
        &notifyFilter,
        DEVICE_NOTIFY_WINDOW_HANDLE
    );

    FireEvent(ALERT_INFO, "USB Monitor: сессия запущена", "{\"event\":\"session_start\"}");

    // 4. Message Loop
    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // 5. Очистка при выходе из цикла
    if (m_hNotify) {
        UnregisterDeviceNotification(m_hNotify);
        m_hNotify = nullptr;
    }

    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }

    FireEvent(ALERT_INFO, "USB Monitor: сессия остановлена", "{\"event\":\"session_stop\"}");
}

// -----------------------------------------------------------------------
// StaticWndProc — статическая оконная процедура (делегирует в экземпляр)
// -----------------------------------------------------------------------

/*static*/ LRESULT CALLBACK UsbMonitor::StaticWndProc(
    HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    // При создании окна LPCREATESTRUCT содержит наш this-указатель
    if (msg == WM_CREATE) {
        auto* cs = reinterpret_cast<LPCREATESTRUCTW>(lParam);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA,
                          reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
        return 0;
    }

    // Для всех остальных сообщений получаем наш экземпляр
    auto* monitor = reinterpret_cast<UsbMonitor*>(
        GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    if (monitor && msg == WM_DEVICECHANGE) {
        return monitor->HandleDeviceChange(wParam, lParam);
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// -----------------------------------------------------------------------
// HandleDeviceChange — обработка WM_DEVICECHANGE
// -----------------------------------------------------------------------

LRESULT UsbMonitor::HandleDeviceChange(WPARAM wParam, LPARAM lParam) {
    if (!m_running.load()) return TRUE;

    // Нас интересуют только два сообщения:
    if (wParam != DBT_DEVICEARRIVAL && wParam != DBT_DEVICEREMOVECOMPLETE) {
        return TRUE;
    }

    if (lParam == 0) return TRUE;

    auto* header = reinterpret_cast<PDEV_BROADCAST_HDR>(lParam);

    // Фильтруем по типу — нам нужны только логические тома (DBT_DEVTYP_VOLUME)
    if (header->dbch_devicetype != DBT_DEVTYP_VOLUME) {
        return TRUE;
    }

    auto* vol = reinterpret_cast<PDEV_BROADCAST_VOLUME>(lParam);

    // Разбираем bitmask букв дисков (может прийти несколько сразу)
    DWORD mask = vol->dbcv_unitmask;
    for (char letter = 'A'; letter <= 'Z'; ++letter) {
        if (mask & 1) {
            if (wParam == DBT_DEVICEARRIVAL) {
                OnVolumeArrival(letter);
            } else {
                OnVolumeRemoved(letter);
            }
        }
        mask >>= 1;
    }

    return TRUE;
}

// -----------------------------------------------------------------------
// OnVolumeArrival — подключена флешка
// -----------------------------------------------------------------------

void UsbMonitor::OnVolumeArrival(char driveLetter) {
    UsbDeviceInfo device{};
    device.driveLetter = std::string(1, driveLetter) + ":";
    device.connectedAt = NowUnix();
    device.disconnectedAt = 0;
    device.state = UsbDeviceState::CONNECTED;

    // Пытаемся получить метаданные, но не блокируем если не удалось (привод CD и т.д.)
    CollectDeviceInfo(driveLetter, device);

    {
        std::lock_guard<std::mutex> lock(m_devicesMutex);
        m_devices.push_back(device);
    }

    // Применяем политику
    ApplyPolicy(device);
}

// -----------------------------------------------------------------------
// OnVolumeRemoved — флешка извлечена (пользователем или ОС)
// -----------------------------------------------------------------------

void UsbMonitor::OnVolumeRemoved(char driveLetter) {
    std::string drive = std::string(1, driveLetter) + ":";
    int64_t now = NowUnix();

    {
        std::lock_guard<std::mutex> lock(m_devicesMutex);
        // Находим последнюю запись с этой буквой и отмечаем время отключения
        for (auto it = m_devices.rbegin(); it != m_devices.rend(); ++it) {
            if (it->driveLetter == drive && it->disconnectedAt == 0) {
                it->disconnectedAt = now;
                it->state = UsbDeviceState::DISCONNECTED;
                break;
            }
        }
    }

    std::string msg = "USB носитель отключён: " + drive;
    std::string details = "{\"drive\":\"" + drive + "\",\"event\":\"removed\"}";
    FireEvent(ALERT_INFO, msg.c_str(), details.c_str());
}

// -----------------------------------------------------------------------
// ApplyPolicy — применяем политику к подключённому носителю
// -----------------------------------------------------------------------

void UsbMonitor::ApplyPolicy(const UsbDeviceInfo& device) {
    std::string drive = device.driveLetter;

    // Формируем JSON с информацией об устройстве
    std::ostringstream detailsOss;
    detailsOss << "{\"drive\":\"" << drive
               << "\",\"label\":\"" << device.volumeLabel
               << "\",\"serial\":\"" << device.volumeSerialHex
               << "\",\"total_gb\":" << std::fixed << std::setprecision(1)
               << (static_cast<double>(device.totalBytes) / (1024.0 * 1024.0 * 1024.0))
               << ",\"policy\":";

    switch (m_policy) {
        case USB_POLICY_ALLOWED: {
            detailsOss << "\"ALLOWED\"}";
            std::string msg = "Подключён USB носитель: " + drive;
            FireEvent(ALERT_INFO, msg.c_str(), detailsOss.str().c_str());
            break;
        }

        case USB_POLICY_READ_ONLY: {
            // Устанавливаем защиту от записи через реестр
            SetUsbWriteProtect(true);
            detailsOss << "\"READ_ONLY\"}";
            std::string msg = "USB носитель переведён в режим только-чтения: " + drive;
            FireEvent(ALERT_WARNING, msg.c_str(), detailsOss.str().c_str());
            break;
        }

        case USB_POLICY_BLOCKED: {
            detailsOss << "\"BLOCKED\"}";
            // Сначала шлём алерт, потом извлекаем
            std::string msg = "USB носитель заблокирован и извлечён: " + drive;
            FireEvent(ALERT_WARNING, msg.c_str(), detailsOss.str().c_str());

            // Программное извлечение с небольшой задержкой
            // (ОС нужно время для монтирования тома прежде чем мы его демонтируем)
            Sleep(500);
            EjectVolume(device.driveLetter[0]);

            // Обновляем состояние в статистике
            {
                std::lock_guard<std::mutex> lock(m_devicesMutex);
                for (auto it = m_devices.rbegin(); it != m_devices.rend(); ++it) {
                    if (it->driveLetter == drive && it->state == UsbDeviceState::CONNECTED) {
                        it->state = UsbDeviceState::EJECTED;
                        it->disconnectedAt = NowUnix();
                        break;
                    }
                }
            }
            break;
        }
    }
}

// -----------------------------------------------------------------------
// EjectVolume — программное безопасное извлечение носителя
// -----------------------------------------------------------------------

bool UsbMonitor::EjectVolume(char driveLetter) {
    // Шаг 1: Открываем том по букве диска
    std::wstring drivePath = L"\\\\.\\" + std::wstring(1, driveLetter) + L":";
    HANDLE hVol = CreateFileW(
        drivePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr
    );

    if (hVol == INVALID_HANDLE_VALUE) return false;

    DWORD bytesRet = 0;
    bool success = false;

    // Шаг 2: Блокируем том (lock), чтобы получить эксклюзивный доступ
    DeviceIoControl(hVol, FSCTL_LOCK_VOLUME, nullptr, 0, nullptr, 0, &bytesRet, nullptr);

    // Шаг 3: Демонтируем файловую систему (flush + dismount)
    DeviceIoControl(hVol, FSCTL_DISMOUNT_VOLUME, nullptr, 0, nullptr, 0, &bytesRet, nullptr);

    // Шаг 4: Даём команду носителю физически извлечься
    success = (DeviceIoControl(hVol, IOCTL_STORAGE_EJECT_MEDIA,
        nullptr, 0, nullptr, 0, &bytesRet, nullptr) != FALSE);

    CloseHandle(hVol);
    return success;
}

// -----------------------------------------------------------------------
// SetUsbWriteProtect — реестровая защита от записи на USB Mass Storage
// -----------------------------------------------------------------------

/*static*/ bool UsbMonitor::SetUsbWriteProtect(bool protect) {
    const wchar_t* KEY_PATH = L"SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies";
    HKEY hKey = nullptr;

    // RegCreateKeyExW создаёт ключ если его нет, или открывает существующий
    LSTATUS res = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE, KEY_PATH, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hKey, nullptr
    );

    if (res != ERROR_SUCCESS || hKey == nullptr) return false;

    DWORD value = protect ? 1 : 0;
    res = RegSetValueExW(hKey, L"WriteProtect", 0, REG_DWORD,
                         reinterpret_cast<const BYTE*>(&value), sizeof(value));

    RegCloseKey(hKey);
    return (res == ERROR_SUCCESS);
}

// -----------------------------------------------------------------------
// CollectDeviceInfo — получаем метаданные о томе
// -----------------------------------------------------------------------

/*static*/ bool UsbMonitor::CollectDeviceInfo(char driveLetter, UsbDeviceInfo& out) {
    std::string rootPath = std::string(1, driveLetter) + ":\\";

    char  volumeLabel[MAX_PATH]   = {};
    char  fsType[MAX_PATH]        = {};
    DWORD serialNumber            = 0;
    DWORD maxComponentLen         = 0;
    DWORD fsFlags                 = 0;

    BOOL ok = GetVolumeInformationA(
        rootPath.c_str(),
        volumeLabel, sizeof(volumeLabel),
        &serialNumber, &maxComponentLen, &fsFlags,
        fsType, sizeof(fsType)
    );

    if (!ok) return false;

    out.volumeLabel = volumeLabel;

    // Форматируем серийный номер как hex (например "A1B2C3D4")
    std::ostringstream hexOss;
    hexOss << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << serialNumber;
    out.volumeSerialHex = hexOss.str();

    // Получаем размер тома
    ULARGE_INTEGER freeBytesAvail{}, totalBytes{}, totalFreeBytes{};
    if (GetDiskFreeSpaceExA(rootPath.c_str(), &freeBytesAvail, &totalBytes, &totalFreeBytes)) {
        out.totalBytes = totalBytes.QuadPart;
        out.freeBytes  = totalFreeBytes.QuadPart;
    }

    return true;
}

// -----------------------------------------------------------------------
// FireEvent
// -----------------------------------------------------------------------

void UsbMonitor::FireEvent(AlertLevel level, const char* message, const char* details) {
    if (m_callback == nullptr) return;

    SystemEvent ev{};
    ev.module    = MODULE_USB;
    ev.level     = level;
    ev.timestamp = NowUnix();
    strncpy_s(ev.message, sizeof(ev.message), message, _TRUNCATE);
    strncpy_s(ev.details, sizeof(ev.details), details, _TRUNCATE);

    m_callback(&ev);
}

// -----------------------------------------------------------------------
// GetReport
// -----------------------------------------------------------------------

void UsbMonitor::GetReport(std::string& out) const {
    std::lock_guard<std::mutex> lock(m_devicesMutex);

    const char* policyStr = "ALLOWED";
    if (m_policy == USB_POLICY_READ_ONLY) policyStr = "READ_ONLY";
    else if (m_policy == USB_POLICY_BLOCKED) policyStr = "BLOCKED";

    std::ostringstream oss;
    oss << "{\n  \"module\": \"USB\",\n";
    oss << "  \"policy\": \"" << policyStr << "\",\n";
    oss << "  \"total_events\": " << m_devices.size() << ",\n";
    oss << "  \"devices\": [\n";

    bool first = true;
    for (const auto& d : m_devices) {
        if (!first) oss << ",\n";
        first = false;

        const char* stateStr = "CONNECTED";
        if (d.state == UsbDeviceState::DISCONNECTED) stateStr = "DISCONNECTED";
        else if (d.state == UsbDeviceState::EJECTED)  stateStr = "EJECTED";

        oss << "    {"
            << "\"drive\": \"" << d.driveLetter << "\""
            << ", \"label\": \"" << d.volumeLabel << "\""
            << ", \"serial\": \"" << d.volumeSerialHex << "\""
            << ", \"total_gb\": " << std::fixed << std::setprecision(1)
            << (static_cast<double>(d.totalBytes) / (1024.0 * 1024.0 * 1024.0))
            << ", \"state\": \"" << stateStr << "\""
            << ", \"connected_at\": " << d.connectedAt
            << ", \"disconnected_at\": " << d.disconnectedAt
            << "}";
    }

    oss << "\n  ]\n}";
    out = oss.str();
}

// -----------------------------------------------------------------------
// Тестовая заглушка
// -----------------------------------------------------------------------

void UsbMonitor::SendTestEvent() {
    FireEvent(ALERT_WARNING,
              "USB носитель заблокирован и извлечён: F:",
              "{\"drive\":\"F:\",\"label\":\"TEST_FLASH\",\"serial\":\"DEADBEEF\","
              "\"total_gb\":14.9,\"policy\":\"BLOCKED\",\"state\":\"EJECTED\"}");
}
