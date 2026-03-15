// =============================================================================
// MonitoringApiWrapper.cs
// P/Invoke обёртка для MonitoringCore.dll
//
// Автор: (команда C++)  |  Назначение: интеграция в WinForms-клиент
// Целевая платформа:    Windows x64, .NET Framework 4.7.2+ / .NET 6+
//
// ─── КАК ИСПОЛЬЗОВАТЬ (инструкция для GUI-разработчиков) ───────────────────
//
// ШАГ 1 — Настройка проекта:
//   • MonitoringCore.dll должна лежать рядом с вашим .exe (или в PATH).
//   • Убедитесь, что ваш проект собирается под x64 (Platform Target = x64),
//     так как DLL компилируется только для x64.
//
// ШАГ 2 — Инициализация (ОДИН РАЗ при запуске приложения, до сессии):
//
//     private MonitoringApiWrapper _monitoring;
//
//     void Application_Startup()
//     {
//         _monitoring = new MonitoringApiWrapper();
//         _monitoring.OnEvent += HandleMonitoringEvent;       // подписка на события
//         _monitoring.Initialize();                           // инит DLL
//     }
//
// ШАГ 3 — Запуск сессии (когда преподаватель нажимает "Начать сессию"):
//
//     void StartSessionButton_Click(...)
//     {
//         var config = new SessionConfig
//         {
//             DnsWhitelist = new[] { "*.google.com", "classroom.google.com", "moodle.edu.ru" },
//             UsbPolicy    = UsbPolicy.Blocked
//         };
//         _monitoring.StartSession(config);
//     }
//
// ШАГ 4 — Обработка событий (вызывается из фонового потока!):
//
//     void HandleMonitoringEvent(MonitoringEvent evt)
//     {
//         // ВАЖНО: событие приходит из C++ потока, обновлять UI нужно через Invoke
//         this.BeginInvoke((Action)(() =>
//         {
//             string icon = evt.Level == AlertLevel.Critical ? "🔴" :
//                           evt.Level == AlertLevel.Warning  ? "🟡" : "🔵";
//             alertLog.Items.Add($"{evt.Time:HH:mm:ss} {icon} [{evt.Module}] {evt.Message}");
//         }));
//     }
//
// ШАГ 5 — Остановка сессии (кнопка "Завершить сессию"):
//
//     void StopSessionButton_Click(...)
//     {
//         _monitoring.StopSession();
//         string report = _monitoring.GetReport();  // JSON-отчёт для преподавателя
//         // ... передать report в сетевой слой или показать в UI
//     }
//
// ШАГ 6 — Завершение приложения:
//
//     void Application_Exit()
//     {
//         _monitoring.Dispose();   // снимает хуки, освобождает все ресурсы
//     }
//
// =============================================================================

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace MonitoringCore
{
    // =========================================================================
    // РАЗДЕЛ 1: Перечисления (зеркалируют C++ enum из monitoring_api.h)
    // =========================================================================

    /// <summary>
    /// Уровень критичности события. Соответствует AlertLevel в C++.
    /// </summary>
    public enum AlertLevel : int
    {
        Info     = 0,   // Информационное (флешка подключена, обычный DNS-запрос)
        Warning  = 1,   // Предупреждение (флешка заблокирована)
        Critical = 2    // Нарушение (DNS-запрос к запрещённому сайту)
    }

    /// <summary>
    /// Источник события (модуль). Соответствует ModuleType в C++.
    /// </summary>
    public enum ModuleType : int
    {
        System = 0,  // Системные события (старт/стоп сессии)
        Dns    = 1,  // DNS Monitor (Задача Мусаева)
        Usb    = 2   // USB Monitor (Задача Шокирова)
    }

    /// <summary>
    /// Политика обработки USB-носителей. Соответствует UsbPolicy в C++.
    /// </summary>
    public enum UsbPolicy : int
    {
        Allowed  = 0,  // Разрешено; преподаватель получает INFO-уведомление
        ReadOnly = 1,  // Носитель монтируется только для чтения
        Blocked  = 2   // Носитель немедленно программно извлекается
    }

    // =========================================================================
    // РАЗДЕЛ 2: Blittable-структура SystemEvent для P/Invoke
    //
    // КРИТИЧЕСКИ ВАЖНО: Pack = 1 обязателен — C++ использует #pragma pack(1).
    // Без этого смещения полей не совпадут и данные будут читаться неверно.
    // =========================================================================

    /// <summary>
    /// Структура события, передаваемая из C++ через коллбек. Blittable (без копирования).
    /// Не изменяйте Pack, порядок и типы полей — они жёстко привязаны к C++ layout.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    internal struct NativeSystemEvent
    {
        public ModuleType Module;                              // 4 байта
        public AlertLevel Level;                               // 4 байта
        public long       Timestamp;                           // 8 байт (int64_t)

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string     Message;                             // 256 байт

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 1024)]
        public string     Details;                             // 1024 байта
        // Итого: 4+4+8+256+1024 = 1296 байт (совпадает с C++ sizeof(SystemEvent))
    }

    // =========================================================================
    // РАЗДЕЛ 3: Конфигурация сессии (управляемый класс для GUI)
    //
    // SessionConfig в C++ содержит char** (массив указателей на строки) —
    // это нельзя маршаллировать автоматически. Маршаллинг выполняется вручную
    // в MonitoringApiWrapper.StartSession() через IntPtr + Marshal.
    // =========================================================================

    /// <summary>
    /// Конфигурация сессии мониторинга. Заполняется формой преподавателя.
    /// </summary>
    public class SessionConfig
    {
        /// <summary>
        /// Список разрешённых доменов/масок для DNS-фильтра.
        /// Примеры: "google.com", "*.microsoft.com", "classroom.google.com"
        /// Пустой список = блокировать ВСЕ DNS-запросы.
        /// </summary>
        public string[] DnsWhitelist { get; set; } = Array.Empty<string>();

        /// <summary>
        /// Политика обработки подключаемых USB-носителей.
        /// </summary>
        public UsbPolicy UsbPolicy { get; set; } = UsbPolicy.Blocked;
    }

    // =========================================================================
    // РАЗДЕЛ 4: Удобный управляемый класс события (для GUI)
    // Преобразует сырой NativeSystemEvent в удобный для обработки объект.
    // =========================================================================

    /// <summary>
    /// Управляемое представление события мониторинга (удобно использовать в GUI).
    /// </summary>
    public class MonitoringEvent
    {
        public ModuleType Module  { get; }
        public AlertLevel Level   { get; }
        public DateTime   Time    { get; }
        public string     Message { get; }
        public string     Details { get; }  // JSON-строка с дополнительными данными

        internal MonitoringEvent(NativeSystemEvent native)
        {
            Module  = native.Module;
            Level   = native.Level;
            // Конвертируем Unix timestamp в локальное время
            Time    = DateTimeOffset.FromUnixTimeSeconds(native.Timestamp).LocalDateTime;
            Message = native.Message ?? string.Empty;
            Details = native.Details ?? string.Empty;
        }

        public override string ToString() =>
            $"[{Time:HH:mm:ss}] [{Level}] [{Module}] {Message}";
    }

    // =========================================================================
    // РАЗДЕЛ 5: Нативные P/Invoke-объявления (внутренние, скрыты от GUI)
    // =========================================================================

    internal static class NativeApi
    {
        private const string DllName = "MonitoringCore.dll";

        // Тип делегата коллбека — ДОЛЖЕН соответствовать typedef void(__cdecl*) в C++
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void NativeEventCallback(ref NativeSystemEvent eventData);

        /// <summary>Инициализация модулей. Вызывать ПЕРВЫМ.</summary>
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "InitModules")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool InitModules(NativeEventCallback callback);

        /// <summary>
        /// Запуск сессии. SessionConfig передаётся как IntPtr на нативную структуру,
        /// сборка которой выполняется вручную в StartSession().
        /// </summary>
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "StartSession")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool StartSession(IntPtr configPtr);

        /// <summary>Остановка сессии. Статистика сохраняется.</summary>
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "StopSession")]
        internal static extern void StopSession();

        /// <summary>Полное освобождение ресурсов DLL. Вызывать при закрытии приложения.</summary>
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "ShutdownModules")]
        internal static extern void ShutdownModules();

        /// <summary>Получить JSON-отчёт за сессию.</summary>
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "GetSessionReport")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetSessionReport(
            [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] byte[] buffer,
            int bufferSize);
    }

    // =========================================================================
    // РАЗДЕЛ 6: MonitoringApiWrapper — главный публичный класс для GUI
    // =========================================================================

    /// <summary>
    /// Управляемая обёртка над MonitoringCore.dll.
    /// Потокобезопасна для вызовов Initialize/StartSession/StopSession/Dispose.
    /// Событие OnEvent вызывается из нативного потока — используйте BeginInvoke в обработчике.
    /// </summary>
    public sealed class MonitoringApiWrapper : IDisposable
    {
        // ── Поле для удержания делегата от сборщика мусора ──────────────────
        // КРИТИЧЕСКИ ВАЖНО: если не хранить ссылку на делегат в поле класса,
        // GC может собрать его прямо во время работы C++ (после завершения
        // метода Initialize). Это приведёт к AccessViolationException.
        private NativeApi.NativeEventCallback _pinnedCallback;

        private bool _initialized = false;
        private bool _disposed    = false;

        // ── DNS Proxy (C# замена MinHook-перехвата DNS) ──────────────────────
        private LocalDnsProxy _dnsProxy;

        // ── Публичное событие ────────────────────────────────────────────────
        /// <summary>
        /// Срабатывает при каждом событии из C++ модулей (DNS или USB).
        /// ВНИМАНИЕ: вызывается из нативного фонового потока.
        /// Для обновления UI используйте Control.BeginInvoke().
        /// </summary>
        public event Action<MonitoringEvent> OnEvent;

        // =====================================================================
        // Initialize — шаг 1 жизненного цикла
        // =====================================================================

        /// <summary>
        /// Инициализирует DLL и регистрирует коллбек.
        /// Вызывайте один раз при старте приложения.
        /// </summary>
        /// <exception cref="InvalidOperationException">Если DLL вернула ошибку.</exception>
        /// <exception cref="DllNotFoundException">Если MonitoringCore.dll не найдена.</exception>
        public void Initialize()
        {
            if (_initialized) return;

            // Создаём делегат и сохраняем в _pinnedCallback (удерживаем от GC)
            _pinnedCallback = OnNativeEvent;

            bool ok = NativeApi.InitModules(_pinnedCallback);
            if (!ok)
                throw new InvalidOperationException(
                    "MonitoringCore: InitModules вернул FALSE. " +
                    "Убедитесь, что приложение запущено с правами Администратора.");

            _initialized = true;
        }

        // =====================================================================
        // StartSession — шаг 2 жизненного цикла
        // =====================================================================

        /// <summary>
        /// Запускает сессию мониторинга с заданными правилами.
        /// Вызывайте после Initialize().
        /// </summary>
        /// <param name="config">Конфигурация сессии от преподавателя.</param>
        /// <exception cref="InvalidOperationException">Если не был вызван Initialize().</exception>
        public void StartSession(SessionConfig config)
        {
            if (!_initialized)
                throw new InvalidOperationException("Сначала вызовите Initialize().");
            if (config == null)
                throw new ArgumentNullException(nameof(config));

            // ── Шаг A: Запуск C++ модуля USB через P/Invoke ─────────────────
            // Маршаллим конфигурацию для C++ (USB-мониторинг остаётся в DLL)
            {
                string[] whitelist      = config.DnsWhitelist ?? Array.Empty<string>();
                int      whitelistCount = whitelist.Length;

                IntPtr[] strPointers = new IntPtr[whitelistCount];
                for (int i = 0; i < whitelistCount; i++)
                    strPointers[i] = Marshal.StringToHGlobalAnsi(whitelist[i] ?? string.Empty);

                IntPtr ppStrings = IntPtr.Zero;
                if (whitelistCount > 0)
                {
                    ppStrings = Marshal.AllocHGlobal(IntPtr.Size * whitelistCount);
                    for (int i = 0; i < whitelistCount; i++)
                        Marshal.WriteIntPtr(ppStrings, i * IntPtr.Size, strPointers[i]);
                }

                IntPtr configPtr = Marshal.AllocHGlobal(IntPtr.Size + 4 + 4);
                try
                {
                    Marshal.WriteIntPtr(configPtr, 0, ppStrings);
                    Marshal.WriteInt32(configPtr, IntPtr.Size, whitelistCount);
                    Marshal.WriteInt32(configPtr, IntPtr.Size + 4, (int)config.UsbPolicy);

                    // C++ DLL теперь используется только для USB-модуля,
                    // но вызов StartSession по-прежнему нужен для обратной совместимости
                    NativeApi.StartSession(configPtr);
                }
                finally
                {
                    Marshal.FreeHGlobal(configPtr);
                    if (ppStrings != IntPtr.Zero)
                        Marshal.FreeHGlobal(ppStrings);
                    foreach (IntPtr p in strPointers)
                        Marshal.FreeHGlobal(p);
                }
            }

            // ── Шаг B: Запуск DNS-прокси (C# замена MinHook хуков) ───────────
            // Порядок критичен: сначала настраиваем систему, потом запускаем прокси
            try
            {
                // 1. Отключаем DoH в браузерах (иначе запросы пойдут мимо порта 53)
                NetworkManager.DisableBrowserDoH();

                // 2. Запускаем UDP DNS-сервер на 127.0.0.1:53
                _dnsProxy?.Dispose();
                _dnsProxy = new LocalDnsProxy();
                _dnsProxy.Start(config.DnsWhitelist, OnDnsProxyAlert);

                // 3. Переключаем DNS системы на наш прокси
                NetworkManager.SetDnsToLocalProxy();

                // 4. Очищаем DNS-кэш, чтобы запросы пошли заново
                NetworkManager.FlushDnsCache();
            }
            catch (Exception ex)
            {
                // При ошибке — откатываем все изменения, чтобы не "сломать" интернет
                NetworkManager.EmergencyRestore();
                _dnsProxy?.Dispose();
                _dnsProxy = null;
                throw new InvalidOperationException(
                    $"DNS Proxy: ошибка запуска — {ex.Message}", ex);
            }
        }

        // =====================================================================
        // StopSession — шаг 3 жизненного цикла
        // =====================================================================

        /// <summary>
        /// Останавливает активную сессию. Статистика инцидентов сохраняется
        /// и доступна через GetReport() до следующего вызова StartSession().
        /// </summary>
        public void StopSession()
        {
            if (!_initialized) return;

            // ── Останавливаем DNS-прокси (C#) ────────────────────────────────
            // Порядок: сначала восстанавливаем DNS → потом останавливаем прокси
            // (иначе запросы пойдут на 127.0.0.1:53, где уже никто не слушает)
            try
            {
                NetworkManager.RestoreDns();
                NetworkManager.RestoreBrowserDoH();
                NetworkManager.FlushDnsCache();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[Wrapper] Ошибка восстановления DNS: {ex.Message}");
            }

            if (_dnsProxy != null)
            {
                _dnsProxy.StopAsync().GetAwaiter().GetResult();
                _dnsProxy.Dispose();
                _dnsProxy = null;
            }

            // ── Останавливаем C++ модули (USB) ───────────────────────────────
            NativeApi.StopSession();
        }

        // =====================================================================
        // GetReport — получение отчёта после StopSession
        // =====================================================================

        /// <summary>
        /// Возвращает агрегированный JSON-отчёт об инцидентах за сессию.
        /// Вызывайте после StopSession() и до следующего StartSession().
        /// </summary>
        /// <returns>
        /// JSON-строка в формате:
        /// <code>
        /// {
        ///   "dns": { "module": "DNS", "blocked_count": 3, "incidents": [...] },
        ///   "usb": { "module": "USB", "policy": "BLOCKED", "total_events": 1, "devices": [...] }
        /// }
        /// </code>
        /// </returns>
        public string GetReport()
        {
            if (!_initialized) return "{}";

            // ── Отчёт от C++ (USB) ───────────────────────────────────────────
            const int BufferSize = 65536;
            byte[] buffer = new byte[BufferSize];

            string usbReport = "{}";
            bool ok = NativeApi.GetSessionReport(buffer, BufferSize);
            if (ok)
            {
                int length = Array.IndexOf(buffer, (byte)0);
                if (length < 0) length = BufferSize;
                usbReport = Encoding.UTF8.GetString(buffer, 0, length);
            }

            // ── Отчёт от DNS-прокси (C#) ─────────────────────────────────────
            string dnsReport = _dnsProxy?.GetReport() ?? "{}";

            // Объединяем в единый JSON
            return $"{{\n  \"dns\": {dnsReport},\n  \"usb\": {usbReport}\n}}";

        // =====================================================================
        // IDisposable — шаг 4 (финальный)
        // =====================================================================

        /// <summary>
        /// Освобождает все ресурсы DLL. Вызывайте при закрытии приложения.
        /// После Dispose() экземпляр нельзя использовать повторно.
        /// </summary>
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            // ── Аварийное восстановление DNS (на случай если StopSession не вызван) ──
            try
            {
                NetworkManager.EmergencyRestore();
            }
            catch { /* ignore — мы в финализаторе */ }

            // ── Останавливаем DNS-прокси ─────────────────────────────────────
            if (_dnsProxy != null)
            {
                try
                {
                    _dnsProxy.StopAsync().GetAwaiter().GetResult();
                    _dnsProxy.Dispose();
                }
                catch { /* ignore */ }
                _dnsProxy = null;
            }

            // ── Останавливаем C++ модули ─────────────────────────────────────
            if (_initialized)
            {
                NativeApi.StopSession();
                NativeApi.ShutdownModules();
                _initialized = false;
            }

            _pinnedCallback = null;
        }

        // =====================================================================
        // Приватный обработчик нативного коллбека
        // =====================================================================

        /// <summary>
        /// Вызывается напрямую из C++ (нативный поток).
        /// Конвертирует сырые данные и передаёт подписчикам через OnEvent.
        /// </summary>
        private void OnNativeEvent(ref NativeSystemEvent nativeEvt)
        {
            try
            {
                var evt = new MonitoringEvent(nativeEvt);
                OnEvent?.Invoke(evt);
            }
            catch
            {
                // Исключения из коллбека нельзя "пробрасывать" в C++ —
                // проглатываем их здесь.
            }
        }

        // =====================================================================
        // Обработчик алертов от DNS-прокси (C#)
        // =====================================================================

        /// <summary>
        /// Вызывается из LocalDnsProxy при блокировке DNS-запроса.
        /// Конвертирует алерт в MonitoringEvent и прокидывает через OnEvent.
        /// </summary>
        private void OnDnsProxyAlert(AlertLevel level, string message, string details)
        {
            try
            {
                // Создаём псевдо-нативное событие для единообразия с USB-событиями
                var nativeEvt = new NativeSystemEvent
                {
                    Module    = ModuleType.Dns,
                    Level     = level,
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    Message   = message?.Length > 255 ? message.Substring(0, 255) : message ?? "",
                    Details   = details?.Length > 1023 ? details.Substring(0, 1023) : details ?? "{}"
                };
                var evt = new MonitoringEvent(nativeEvt);
                OnEvent?.Invoke(evt);
            }
            catch { /* проглатываем — алерт не должен ронять приложение */ }
        }
    }
}
