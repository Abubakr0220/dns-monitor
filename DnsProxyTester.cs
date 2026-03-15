// =============================================================================
// DnsProxyTester.cs
// Консольный тестер для DNS-прокси мониторинга.
//
// Использование:
//   1. Собрать проект (MonitoringCore.dll должна лежать рядом с .exe)
//   2. Запустить от имени Администратора
//   3. Проверить в браузере: разрешённые сайты открываются, запрещённые — нет
//   4. Нажать Enter для остановки
//
// ВАЖНО: программа регистрирует CancelKeyPress и ProcessExit для гарантированного
//        восстановления DNS при аварийном завершении (Ctrl+C, закрытие окна).
// =============================================================================

using System;
using System.Threading;

namespace MonitoringCore
{
    class DnsProxyTester
    {
        // Флаг для предотвращения двойного восстановления
        private static int _cleanupDone = 0;
        private static MonitoringApiWrapper _monitoring;

        static void Main(string[] args)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            Console.Title = "MonitoringCore — DNS Proxy Tester";

            Console.WriteLine("═══════════════════════════════════════════════════════");
            Console.WriteLine("  MonitoringCore — Тестер DNS-прокси");
            Console.WriteLine("  Запускайте от имени Администратора!");
            Console.WriteLine("═══════════════════════════════════════════════════════");
            Console.WriteLine();

            // ── Регистрируем аварийные обработчики ─────────────────────────
            // Ctrl+C или закрытие окна консоли
            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true; // Не завершаем процесс мгновенно — даём выполнить cleanup
                Console.WriteLine("\n⚠️ Ctrl+C — останавливаем...");
                SafeCleanup();
                Environment.Exit(0);
            };

            // Завершение процесса (закрытие окна, TaskManager и т.д.)
            AppDomain.CurrentDomain.ProcessExit += (sender, e) =>
            {
                SafeCleanup();
            };

            try
            {
                // ── Шаг 1: Инициализация ──────────────────────────────────
                _monitoring = new MonitoringApiWrapper();
                _monitoring.OnEvent += HandleMonitoringEvent;

                Console.WriteLine("[Тестер] Инициализация MonitoringCore...");
                _monitoring.Initialize();
                Console.WriteLine("[Тестер] ✅ Инициализация прошла успешно.");
                Console.WriteLine();

                // ── Шаг 2: Конфигурация сессии ────────────────────────────
                var config = new SessionConfig
                {
                    // Белый список: эти домены будут разрешены, остальные заблокированы
                    DnsWhitelist = new[]
                    {
                        "*.google.com",         // Google и все поддомены
                        "*.googleapis.com",      // Google API
                        "*.gstatic.com",         // Google статика
                        "*.microsoft.com",       // Microsoft
                        "*.windows.com",         // Windows Update
                        "*.windowsupdate.com",   // Windows Update
                        "github.com",            // GitHub (точный)
                        "*.github.com",          // GitHub поддомены
                        "*.githubusercontent.com", // GitHub CDN
                        "*.bing.com",            // Bing
                    },
                    UsbPolicy = UsbPolicy.Blocked
                };

                Console.WriteLine("[Тестер] ─── Белый список DNS ───────────────────");
                foreach (var domain in config.DnsWhitelist)
                {
                    Console.WriteLine($"  ✓ {domain}");
                }
                Console.WriteLine();

                // ── Шаг 3: Запуск сессии ──────────────────────────────────
                Console.WriteLine("[Тестер] Запуск сессии мониторинга...");
                _monitoring.StartSession(config);
                Console.WriteLine("[Тестер] ✅ Сессия запущена!");
                Console.WriteLine();
                Console.WriteLine("═══════════════════════════════════════════════════════");
                Console.WriteLine("  Теперь попробуйте открыть в браузере:");
                Console.WriteLine("    ✓ google.com     — должен открыться");
                Console.WriteLine("    ✗ vk.com         — должен быть заблокирован");
                Console.WriteLine("    ✗ youtube.com    — должен быть заблокирован");
                Console.WriteLine("    ✗ telegram.org   — должен быть заблокирован");
                Console.WriteLine();
                Console.WriteLine("  Или через cmd:  nslookup vk.com 127.0.0.1");
                Console.WriteLine("═══════════════════════════════════════════════════════");
                Console.WriteLine();
                Console.WriteLine("  Нажмите [Enter] для остановки сессии...");
                Console.WriteLine();

                // ── Ожидаем ввод ──────────────────────────────────────────
                Console.ReadLine();

                // ── Шаг 4: Остановка ──────────────────────────────────────
                SafeCleanup();

                // ── Шаг 5: Отчёт ─────────────────────────────────────────
                Console.WriteLine();
                Console.WriteLine("═══════════════════════════════════════════════════════");
                Console.WriteLine("  JSON-отчёт за сессию:");
                Console.WriteLine("═══════════════════════════════════════════════════════");
                string report = _monitoring?.GetReport() ?? "{}";
                Console.WriteLine(report);
                Console.WriteLine();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"\n❌ ОШИБКА: {ex.Message}");
                Console.Error.WriteLine(ex.StackTrace);

                // Гарантируем восстановление DNS даже при ошибке
                SafeCleanup();
            }

            Console.WriteLine("Нажмите любую клавишу для выхода...");
            Console.ReadKey(true);
        }

        /// <summary>
        /// Безопасная очистка: останавливает сессию и восстанавливает настройки.
        /// Можно вызывать многократно — выполнится только один раз.
        /// </summary>
        private static void SafeCleanup()
        {
            // Interlocked гарантирует, что cleanup выполнится ровно один раз
            // даже при конкурентных вызовах из CancelKeyPress + ProcessExit
            if (Interlocked.CompareExchange(ref _cleanupDone, 1, 0) != 0)
                return;

            Console.WriteLine();
            Console.WriteLine("[Тестер] Остановка сессии...");

            try
            {
                _monitoring?.StopSession();
                Console.WriteLine("[Тестер] ✅ Сессия остановлена, DNS восстановлен.");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[Тестер] Ошибка при остановке: {ex.Message}");
                // Аварийное восстановление
                NetworkManager.EmergencyRestore();
            }
        }

        /// <summary>
        /// Обработчик событий мониторинга (DNS + USB).
        /// </summary>
        private static void HandleMonitoringEvent(MonitoringEvent evt)
        {
            // Выбираем иконку по уровню критичности
            string icon = evt.Level switch
            {
                AlertLevel.Critical => "🔴",
                AlertLevel.Warning  => "🟡",
                _                   => "🔵"
            };

            // Выбираем цвет для консоли
            ConsoleColor color = evt.Level switch
            {
                AlertLevel.Critical => ConsoleColor.Red,
                AlertLevel.Warning  => ConsoleColor.Yellow,
                _                   => ConsoleColor.Cyan
            };

            ConsoleColor prevColor = Console.ForegroundColor;
            Console.ForegroundColor = color;
            Console.WriteLine($"  {icon} {evt}");
            Console.ForegroundColor = prevColor;
        }
    }
}
