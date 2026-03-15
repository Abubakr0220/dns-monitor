// =============================================================================
// NetworkManager.cs
// Управление сетевыми настройками Windows для DNS-прокси мониторинга.
//
// Функции:
//   • Переключение DNS-адреса активных сетевых адаптеров на 127.0.0.1
//   • Восстановление оригинальных DNS-настроек (или DHCP)
//   • Сброс системного DNS-кэша (ipconfig /flushdns)
//   • Отключение / восстановление DNS-over-HTTPS (DoH) в Chrome и Edge
//     через групповые политики (реестр HKLM)
//
// ВАЖНО: все методы требуют прав Администратора.
//        Все методы обёрнуты в try-catch и НЕ бросают исключений наружу —
//        при ошибке возвращают false и пишут в Console.Error.
// =============================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using Microsoft.Win32;

namespace MonitoringCore
{
    /// <summary>
    /// Управляет DNS-настройками системы для работы локального DNS-прокси.
    /// Все методы статические, потокобезопасность обеспечивается порядком вызова
    /// (Start → Stop строго последовательно из MonitoringApiWrapper).
    /// </summary>
    public static class NetworkManager
    {
        // =====================================================================
        // Приватные поля для хранения оригинальных настроек
        // =====================================================================

        /// <summary>
        /// Словарь: Caption адаптера → массив оригинальных DNS-серверов (или null если DHCP).
        /// Заполняется в SetDnsToLocalProxy(), используется в RestoreDns().
        /// </summary>
        private static readonly Dictionary<string, string[]> _savedDnsSettings = new();

        /// <summary>Были ли ключи реестра Chrome DoH созданы нами.</summary>
        private static bool _chromeDoHDisabled = false;

        /// <summary>Были ли ключи реестра Edge DoH созданы нами.</summary>
        private static bool _edgeDoHDisabled = false;

        /// <summary>Были ли DNS-настройки изменены нами.</summary>
        private static bool _dnsChanged = false;

        // =====================================================================
        // DNS: Переключение на локальный прокси
        // =====================================================================

        /// <summary>
        /// Находит все активные сетевые адаптеры с IP, сохраняет их текущие
        /// DNS-настройки и устанавливает DNS на 127.0.0.1.
        /// </summary>
        /// <returns>true если хотя бы один адаптер был переключён успешно.</returns>
        public static bool SetDnsToLocalProxy()
        {
            try
            {
                _savedDnsSettings.Clear();
                int successCount = 0;

                // WMI-запрос: выбираем адаптеры, у которых включён IP и есть
                // хотя бы один IP-адрес (т.е. активные сетевые интерфейсы)
                using var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE");

                foreach (ManagementObject adapter in searcher.Get())
                {
                    try
                    {
                        string caption = adapter["Caption"]?.ToString() ?? "Unknown";

                        // Сохраняем текущие DNS-серверы (может быть null если DHCP)
                        string[] currentDns = adapter["DNSServerSearchOrder"] as string[];
                        _savedDnsSettings[caption] = currentDns; // null = DHCP

                        // Устанавливаем DNS на наш локальный прокси
                        var dnsParams = adapter.GetMethodParameters("SetDNSServerSearchOrder");
                        dnsParams["DNSServerSearchOrder"] = new string[] { "127.0.0.1" };

                        var result = adapter.InvokeMethod("SetDNSServerSearchOrder", dnsParams, null);
                        uint retCode = (uint)result["ReturnValue"];

                        if (retCode == 0) // 0 = успех
                        {
                            successCount++;
                            Console.WriteLine($"[NetworkManager] DNS адаптера \"{caption}\" → 127.0.0.1");
                        }
                        else
                        {
                            Console.Error.WriteLine(
                                $"[NetworkManager] Ошибка WMI SetDNS для \"{caption}\": код {retCode}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine(
                            $"[NetworkManager] Ошибка при настройке адаптера: {ex.Message}");
                    }
                }

                _dnsChanged = successCount > 0;
                return _dnsChanged;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[NetworkManager] SetDnsToLocalProxy FAILED: {ex.Message}");
                return false;
            }
        }

        // =====================================================================
        // DNS: Восстановление оригинальных настроек
        // =====================================================================

        /// <summary>
        /// Восстанавливает DNS-настройки всех адаптеров к сохранённым значениям.
        /// Если оригинальные настройки были DHCP (null), включает DHCP обратно.
        /// </summary>
        /// <returns>true если хотя бы один адаптер восстановлен.</returns>
        public static bool RestoreDns()
        {
            if (!_dnsChanged)
                return true; // Ничего не менялось — ничего не восстанавливаем

            try
            {
                int successCount = 0;

                using var searcher = new ManagementObjectSearcher(
                    "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE");

                foreach (ManagementObject adapter in searcher.Get())
                {
                    try
                    {
                        string caption = adapter["Caption"]?.ToString() ?? "Unknown";

                        // Проверяем, менялся ли этот адаптер
                        if (!_savedDnsSettings.ContainsKey(caption))
                            continue;

                        string[] originalDns = _savedDnsSettings[caption];

                        if (originalDns == null || originalDns.Length == 0)
                        {
                            // Оригинал был DHCP — включаем обратно
                            // SetDNSServerSearchOrder с пустым массивом = вернуть DHCP
                            var dnsParams = adapter.GetMethodParameters("SetDNSServerSearchOrder");
                            dnsParams["DNSServerSearchOrder"] = null;
                            adapter.InvokeMethod("SetDNSServerSearchOrder", dnsParams, null);
                            Console.WriteLine($"[NetworkManager] DNS адаптера \"{caption}\" → DHCP");
                        }
                        else
                        {
                            // Восстанавливаем конкретные DNS-серверы
                            var dnsParams = adapter.GetMethodParameters("SetDNSServerSearchOrder");
                            dnsParams["DNSServerSearchOrder"] = originalDns;
                            adapter.InvokeMethod("SetDNSServerSearchOrder", dnsParams, null);
                            Console.WriteLine(
                                $"[NetworkManager] DNS адаптера \"{caption}\" → [{string.Join(", ", originalDns)}]");
                        }

                        successCount++;
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine(
                            $"[NetworkManager] Ошибка при восстановлении адаптера: {ex.Message}");
                    }
                }

                _savedDnsSettings.Clear();
                _dnsChanged = false;
                return successCount > 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[NetworkManager] RestoreDns FAILED: {ex.Message}");
                return false;
            }
        }

        // =====================================================================
        // DNS Cache: Сброс
        // =====================================================================

        /// <summary>
        /// Выполняет ipconfig /flushdns для очистки системного DNS-кэша.
        /// Это заставляет все приложения делать новые DNS-запросы через наш прокси.
        /// </summary>
        public static bool FlushDnsCache()
        {
            try
            {
                using var process = new Process();
                process.StartInfo = new ProcessStartInfo
                {
                    FileName = "ipconfig",
                    Arguments = "/flushdns",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                process.Start();
                process.WaitForExit(5000); // Макс. 5 секунд

                Console.WriteLine("[NetworkManager] DNS-кэш очищен (ipconfig /flushdns)");
                return process.ExitCode == 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[NetworkManager] FlushDnsCache FAILED: {ex.Message}");
                return false;
            }
        }

        // =====================================================================
        // DoH: Отключение Secure DNS в браузерах через реестр (Group Policy)
        // =====================================================================

        /// <summary>
        /// Отключает DNS-over-HTTPS в Chrome и Edge через ключи групповых политик.
        /// Это критично: если DoH включён, браузер шлёт DNS-запросы по HTTPS
        /// напрямую на dns.google/cloudflare, минуя наш локальный прокси на порту 53.
        /// </summary>
        public static bool DisableBrowserDoH()
        {
            bool ok = true;

            // ── Google Chrome ─────────────────────────────────────────────
            // Ключ: HKLM\Software\Policies\Google\Chrome
            // Значение: DnsOverHttpsMode = "off"
            try
            {
                using var chromeKey = Registry.LocalMachine.CreateSubKey(
                    @"Software\Policies\Google\Chrome", writable: true);

                if (chromeKey != null)
                {
                    chromeKey.SetValue("DnsOverHttpsMode", "off", RegistryValueKind.String);
                    _chromeDoHDisabled = true;
                    Console.WriteLine("[NetworkManager] Chrome DoH отключён (реестр)");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[NetworkManager] Chrome DoH disable FAILED: {ex.Message}");
                ok = false;
            }

            // ── Microsoft Edge ────────────────────────────────────────────
            // Ключ: HKLM\Software\Policies\Microsoft\Edge
            // Значение: DnsOverHttpsMode = "off"
            try
            {
                using var edgeKey = Registry.LocalMachine.CreateSubKey(
                    @"Software\Policies\Microsoft\Edge", writable: true);

                if (edgeKey != null)
                {
                    edgeKey.SetValue("DnsOverHttpsMode", "off", RegistryValueKind.String);
                    _edgeDoHDisabled = true;
                    Console.WriteLine("[NetworkManager] Edge DoH отключён (реестр)");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[NetworkManager] Edge DoH disable FAILED: {ex.Message}");
                ok = false;
            }

            return ok;
        }

        /// <summary>
        /// Удаляет ключи реестра, которые мы создали для отключения DoH.
        /// Если ключи создавались не нами — не трогаем.
        /// </summary>
        public static bool RestoreBrowserDoH()
        {
            bool ok = true;

            // ── Chrome ────────────────────────────────────────────────────
            if (_chromeDoHDisabled)
            {
                try
                {
                    using var chromeKey = Registry.LocalMachine.OpenSubKey(
                        @"Software\Policies\Google\Chrome", writable: true);

                    chromeKey?.DeleteValue("DnsOverHttpsMode", throwOnMissingValue: false);
                    _chromeDoHDisabled = false;
                    Console.WriteLine("[NetworkManager] Chrome DoH восстановлен (ключ удалён)");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(
                        $"[NetworkManager] Chrome DoH restore FAILED: {ex.Message}");
                    ok = false;
                }
            }

            // ── Edge ──────────────────────────────────────────────────────
            if (_edgeDoHDisabled)
            {
                try
                {
                    using var edgeKey = Registry.LocalMachine.OpenSubKey(
                        @"Software\Policies\Microsoft\Edge", writable: true);

                    edgeKey?.DeleteValue("DnsOverHttpsMode", throwOnMissingValue: false);
                    _edgeDoHDisabled = false;
                    Console.WriteLine("[NetworkManager] Edge DoH восстановлен (ключ удалён)");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(
                        $"[NetworkManager] Edge DoH restore FAILED: {ex.Message}");
                    ok = false;
                }
            }

            return ok;
        }

        // =====================================================================
        // Аварийное восстановление (вызывается из ProcessExit / CancelKeyPress)
        // =====================================================================

        /// <summary>
        /// Восстанавливает ВСЕ изменённые настройки. Безопасен для повторного вызова.
        /// Используйте при аварийном завершении программы.
        /// </summary>
        public static void EmergencyRestore()
        {
            Console.WriteLine("[NetworkManager] ⚠️ Аварийное восстановление настроек...");
            RestoreDns();
            RestoreBrowserDoH();
            FlushDnsCache();
        }
    }
}
