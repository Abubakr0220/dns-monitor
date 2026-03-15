// =============================================================================
// LocalDnsProxy.cs
// Локальный UDP DNS-прокси сервер с фильтрацией по белому списку.
//
// Архитектура:
//   • Слушает UDP-порт 53 на 127.0.0.1
//   • Парсит входящие DNS-запросы (извлекает доменное имя)
//   • Проверяет домен по белому списку (точное совпадение + wildcard)
//   • Разрешённые запросы → forward на upstream DNS (8.8.8.8)
//   • Запрещённые запросы → ответ NXDOMAIN + вызов callback алерта
//
// Парсинг DNS wire format:
//   DNS-пакет = Header (12 байт) + Question Section + Answer Section (в ответе)
//   Мы парсим только Question Section для извлечения имени домена.
//   Формат имени: длина-метка-длина-метка-0 (например: 6google3com0)
//
// Примечание: реализация покрывает стандартные A/AAAA-запросы,
//             чего достаточно для учебного проекта.
// =============================================================================

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MonitoringCore
{
    /// <summary>
    /// Делегат для отправки алертов из DNS-прокси в UI.
    /// </summary>
    /// <param name="level">Уровень критичности.</param>
    /// <param name="message">Краткое сообщение.</param>
    /// <param name="details">JSON с деталями.</param>
    public delegate void DnsAlertHandler(AlertLevel level, string message, string details);

    /// <summary>
    /// Локальный DNS-прокси сервер. Слушает UDP 53, фильтрует запросы по белому списку.
    /// </summary>
    public sealed class LocalDnsProxy : IDisposable
    {
        // =====================================================================
        // Константы
        // =====================================================================

        /// <summary>Адрес upstream DNS-сервера для forward'а разрешённых запросов.</summary>
        private static readonly IPEndPoint UpstreamDns = new(IPAddress.Parse("8.8.8.8"), 53);

        /// <summary>Таймаут ожидания ответа от upstream DNS (мс).</summary>
        private const int UpstreamTimeoutMs = 3000;

        /// <summary>Максимальный размер DNS UDP-пакета.</summary>
        private const int MaxDnsPacketSize = 512;

        // =====================================================================
        // Поля
        // =====================================================================

        private UdpClient _listener;
        private CancellationTokenSource _cts;
        private Task _listenTask;

        /// <summary>Белый список: точные домены (lowercase).</summary>
        private readonly HashSet<string> _exactDomains = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Белый список: wildcard-суффиксы (".example.com").</summary>
        private readonly List<string> _wildcardSuffixes = new();

        /// <summary>Callback для отправки алертов в UI.</summary>
        private DnsAlertHandler _onAlert;

        /// <summary>Статистика блокировок: домен → количество попыток.</summary>
        private readonly ConcurrentDictionary<string, int> _blockedStats = new();

        private bool _disposed = false;

        // =====================================================================
        // Запуск / Остановка
        // =====================================================================

        /// <summary>
        /// Запускает DNS-прокси сервер асинхронно.
        /// </summary>
        /// <param name="whitelist">Массив разрешённых доменов/масок.</param>
        /// <param name="onAlert">Callback для алертов.</param>
        public void Start(string[] whitelist, DnsAlertHandler onAlert)
        {
            if (_listenTask != null)
                throw new InvalidOperationException("DNS Proxy уже запущен.");

            _onAlert = onAlert ?? throw new ArgumentNullException(nameof(onAlert));

            // ── Парсим белый список ───────────────────────────────────────
            _exactDomains.Clear();
            _wildcardSuffixes.Clear();
            _blockedStats.Clear();

            foreach (string entry in whitelist ?? Array.Empty<string>())
            {
                if (string.IsNullOrWhiteSpace(entry)) continue;

                string normalized = entry.Trim().ToLowerInvariant();

                if (normalized.StartsWith("*.") && normalized.Length > 2)
                {
                    // Wildcard: "*.google.com" → храним суффикс ".google.com"
                    _wildcardSuffixes.Add(normalized.Substring(1));
                }
                else
                {
                    _exactDomains.Add(normalized);
                }
            }

            // ── Запуск UDP-слушателя ──────────────────────────────────────
            _cts = new CancellationTokenSource();

            // Биндим на 127.0.0.1:53 — только локальные запросы
            _listener = new UdpClient(new IPEndPoint(IPAddress.Loopback, 53));

            _listenTask = Task.Run(() => ListenLoopAsync(_cts.Token));

            Console.WriteLine("[DnsProxy] ✅ DNS Proxy запущен на 127.0.0.1:53");
            Console.WriteLine($"[DnsProxy] Белый список: {_exactDomains.Count} точных, " +
                              $"{_wildcardSuffixes.Count} wildcard");
        }

        /// <summary>
        /// Останавливает DNS-прокси и освобождает порт 53.
        /// </summary>
        public async Task StopAsync()
        {
            if (_listenTask == null) return;

            Console.WriteLine("[DnsProxy] Остановка DNS Proxy...");

            _cts?.Cancel();

            // Закрываем UdpClient — это прервёт блокирующий ReceiveAsync
            try { _listener?.Close(); } catch { /* ignore */ }

            // Ждём завершения таска (макс. 3 секунды)
            if (_listenTask != null)
            {
                try
                {
                    await Task.WhenAny(_listenTask, Task.Delay(3000));
                }
                catch { /* ignore */ }
            }

            _listenTask = null;
            _cts?.Dispose();
            _cts = null;
            _listener = null;

            Console.WriteLine("[DnsProxy] ✅ DNS Proxy остановлен.");
        }

        // =====================================================================
        // Основной цикл приёма пакетов
        // =====================================================================

        private async Task ListenLoopAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    // Ожидаем DNS-запрос от системы (клиент: браузер, curl, nslookup...)
                    UdpReceiveResult received = await _listener.ReceiveAsync();

                    // Обрабатываем каждый запрос асинхронно, не блокируя приём
                    _ = Task.Run(() => HandleQueryAsync(received.Buffer, received.RemoteEndPoint, ct));
                }
                catch (ObjectDisposedException)
                {
                    // UdpClient закрыт в StopAsync — нормальное завершение
                    break;
                }
                catch (SocketException) when (ct.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    if (!ct.IsCancellationRequested)
                    {
                        Console.Error.WriteLine($"[DnsProxy] Ошибка приёма: {ex.Message}");
                    }
                }
            }
        }

        // =====================================================================
        // Обработка одного DNS-запроса
        // =====================================================================

        private async Task HandleQueryAsync(byte[] queryData, IPEndPoint clientEp, CancellationToken ct)
        {
            try
            {
                // Минимальный размер DNS-пакета: 12 байт header + хотя бы 1 байт в question
                if (queryData == null || queryData.Length < 13)
                    return;

                // ── Парсим доменное имя из DNS Question ───────────────────
                string domain = ParseDomainName(queryData);
                if (string.IsNullOrEmpty(domain))
                {
                    // Не удалось распарсить — проксируем как есть (безопасный fallback)
                    await ForwardAndReply(queryData, clientEp, ct);
                    return;
                }

                string normalizedDomain = NormalizeDomain(domain);

                // ── Проверяем белый список ────────────────────────────────
                if (IsDomainAllowed(normalizedDomain))
                {
                    // ✓ Разрешено — проксируем на upstream DNS
                    await ForwardAndReply(queryData, clientEp, ct);
                }
                else
                {
                    // ✗ Запрещено — отвечаем NXDOMAIN
                    byte[] nxResponse = BuildNxDomainResponse(queryData);
                    await SendResponse(nxResponse, clientEp);

                    // Обновляем статистику блокировок
                    int attempts = _blockedStats.AddOrUpdate(normalizedDomain, 1, (_, old) => old + 1);

                    // Отправляем алерт
                    string msg = $"Заблокирован DNS-запрос: {normalizedDomain}";
                    string details = $"{{\"domain\":\"{normalizedDomain}\"," +
                                     $"\"method\":\"DnsProxy\"," +
                                     $"\"attempts\":{attempts}}}";

                    _onAlert?.Invoke(AlertLevel.Critical, msg, details);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[DnsProxy] Ошибка обработки запроса: {ex.Message}");
            }
        }

        // =====================================================================
        // Forward запроса на upstream DNS
        // =====================================================================

        private async Task ForwardAndReply(byte[] queryData, IPEndPoint clientEp, CancellationToken ct)
        {
            try
            {
                using var forwarder = new UdpClient();
                forwarder.Client.ReceiveTimeout = UpstreamTimeoutMs;

                // Отправляем оригинальный запрос на upstream DNS (8.8.8.8:53)
                await forwarder.SendAsync(queryData, queryData.Length, UpstreamDns);

                // Ждём ответа
                var receiveTask = forwarder.ReceiveAsync();
                var completedTask = await Task.WhenAny(receiveTask, Task.Delay(UpstreamTimeoutMs, ct));

                if (completedTask == receiveTask && receiveTask.IsCompletedSuccessfully)
                {
                    byte[] response = receiveTask.Result.Buffer;
                    await SendResponse(response, clientEp);
                }
                else
                {
                    // Таймаут — возвращаем SERVFAIL
                    byte[] servFail = BuildServerFailResponse(queryData);
                    await SendResponse(servFail, clientEp);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[DnsProxy] Forward error: {ex.Message}");

                // При ошибке forward — SERVFAIL
                try
                {
                    byte[] servFail = BuildServerFailResponse(queryData);
                    await SendResponse(servFail, clientEp);
                }
                catch { /* ignore */ }
            }
        }

        private async Task SendResponse(byte[] data, IPEndPoint clientEp)
        {
            try
            {
                if (_listener != null && data != null)
                {
                    await _listener.SendAsync(data, data.Length, clientEp);
                }
            }
            catch (ObjectDisposedException) { /* сервер закрылся */ }
        }

        // =====================================================================
        // DNS Wire Format: Парсинг доменного имени
        // =====================================================================

        /// <summary>
        /// Извлекает доменное имя из DNS-запроса.
        ///
        /// DNS Header: 12 байт
        /// Question Section начинается с 12-го байта.
        /// Формат имени: последовательность (длина, метка), завершающаяся нулём.
        ///   Пример: \x06google\x03com\x00 → "google.com"
        /// </summary>
        private static string ParseDomainName(byte[] packet)
        {
            if (packet.Length < 13) return null;

            int offset = 12; // Пропускаем заголовок (12 байт)
            var parts = new List<string>();

            while (offset < packet.Length)
            {
                byte labelLen = packet[offset];

                // Нулевой байт — конец имени
                if (labelLen == 0) break;

                // Защита от pointer compression (0xC0) — в запросах обычно не встречается,
                // но на всякий случай
                if ((labelLen & 0xC0) == 0xC0) break;

                // Защита от выхода за границы
                if (offset + 1 + labelLen > packet.Length) return null;

                // Читаем метку
                string label = Encoding.ASCII.GetString(packet, offset + 1, labelLen);
                parts.Add(label);

                offset += 1 + labelLen;
            }

            return parts.Count > 0 ? string.Join(".", parts) : null;
        }

        // =====================================================================
        // DNS Wire Format: Сборка ответов
        // =====================================================================

        /// <summary>
        /// Собирает DNS-ответ NXDOMAIN (Response Code = 3).
        /// Копирует Transaction ID и Question Section из запроса,
        /// устанавливает флаги ответа и RCODE = NXDOMAIN.
        /// </summary>
        private static byte[] BuildNxDomainResponse(byte[] query)
        {
            return BuildErrorResponse(query, rcode: 3); // 3 = NXDOMAIN
        }

        /// <summary>
        /// Собирает DNS-ответ SERVFAIL (Response Code = 2).
        /// Используется при ошибках forward'а.
        /// </summary>
        private static byte[] BuildServerFailResponse(byte[] query)
        {
            return BuildErrorResponse(query, rcode: 2); // 2 = SERVFAIL
        }

        /// <summary>
        /// Собирает минимальный DNS-ответ с указанным кодом ошибки.
        ///
        /// Формат DNS Header (12 байт):
        ///   [0-1]  Transaction ID     — копируем из запроса
        ///   [2-3]  Flags              — QR=1 (ответ), RD=1, RA=1, RCODE=rcode
        ///   [4-5]  QDCOUNT            — копируем из запроса (обычно 1)
        ///   [6-7]  ANCOUNT            — 0 (нет ответов)
        ///   [8-9]  NSCOUNT            — 0
        ///   [10-11] ARCOUNT           — 0
        ///   [12+]  Question Section   — копируем из запроса
        /// </summary>
        private static byte[] BuildErrorResponse(byte[] query, byte rcode)
        {
            // Копируем весь запрос (заголовок + question section)
            byte[] response = new byte[query.Length];
            Array.Copy(query, response, query.Length);

            // Byte 2: QR=1 (ответ) | Opcode=0 | AA=1 | TC=0 | RD (из запроса)
            response[2] = (byte)(0x84 | (query[2] & 0x01)); // 0x84 = QR+AA, сохраняем бит RD
            // Byte 3: RA=1 | RCODE
            response[3] = (byte)(0x80 | (rcode & 0x0F));     // 0x80 = RA, rcode в младших 4 битах

            // ANCOUNT = 0 (нет ответов)
            response[6] = 0;
            response[7] = 0;
            // NSCOUNT = 0
            response[8] = 0;
            response[9] = 0;
            // ARCOUNT = 0
            response[10] = 0;
            response[11] = 0;

            return response;
        }

        // =====================================================================
        // Белый список: проверка домена
        // =====================================================================

        /// <summary>
        /// Проверяет, разрешён ли домен по белому списку.
        /// Поддерживает точное совпадение и wildcard-маски (*.example.com).
        /// </summary>
        private bool IsDomainAllowed(string domain)
        {
            // 1. Всегда разрешаем localhost и локальные имена
            if (domain == "localhost" || domain.EndsWith(".local"))
                return true;

            // 2. Точное совпадение (HashSet — O(1))
            if (_exactDomains.Contains(domain))
                return true;

            // 3. Wildcard-суффиксы
            foreach (string suffix in _wildcardSuffixes)
            {
                // suffix = ".google.com"
                // Проверяем поддомен: "maps.google.com".EndsWith(".google.com")
                if (domain.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                    return true;

                // Проверяем базовый домен: "google.com" == "google.com"
                if (suffix.Length > 1 && domain.Equals(suffix.Substring(1), StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Нормализует домен: lowercase + убрать trailing dot.
        /// </summary>
        private static string NormalizeDomain(string domain)
        {
            string result = domain.ToLowerInvariant().Trim();
            if (result.EndsWith("."))
                result = result.TrimEnd('.');
            return result;
        }

        // =====================================================================
        // Отчёт
        // =====================================================================

        /// <summary>
        /// Возвращает JSON-отчёт о заблокированных DNS-запросах за сессию.
        /// </summary>
        public string GetReport()
        {
            var sb = new StringBuilder();
            sb.AppendLine("{");
            sb.AppendLine("  \"module\": \"DNS_PROXY\",");
            sb.AppendLine($"  \"blocked_count\": {_blockedStats.Count},");
            sb.AppendLine("  \"incidents\": [");

            bool first = true;
            foreach (var kvp in _blockedStats)
            {
                if (!first) sb.AppendLine(",");
                first = false;
                sb.Append($"    {{\"domain\": \"{kvp.Key}\", \"attempts\": {kvp.Value}}}");
            }

            sb.AppendLine();
            sb.AppendLine("  ]");
            sb.Append("}");
            return sb.ToString();
        }

        // =====================================================================
        // IDisposable
        // =====================================================================

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            _cts?.Cancel();
            try { _listener?.Close(); } catch { /* ignore */ }
            _cts?.Dispose();
        }
    }
}
