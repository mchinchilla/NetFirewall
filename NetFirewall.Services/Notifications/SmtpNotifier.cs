using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace NetFirewall.Services.Notifications;

/// <summary>
/// SMTP configuration. Bound from the "Notifications:Smtp" section; secrets
/// (Username/Password) belong in the daemon's EnvironmentFile, not appsettings.
/// Disabled (no email sent) unless <see cref="Enabled"/> is true AND a Host +
/// at least one recipient are set.
/// </summary>
public sealed class SmtpNotifierOptions
{
    public const string SectionName = "Notifications:Smtp";

    public bool Enabled        { get; set; }
    public string? Host        { get; set; }
    public int Port            { get; set; } = 587;
    /// <summary>Enable STARTTLS / implicit TLS. Default true (587/465 expect it).</summary>
    public bool UseTls         { get; set; } = true;
    public string? Username    { get; set; }
    public string? Password    { get; set; }
    /// <summary>From address. Falls back to Username when unset.</summary>
    public string? From        { get; set; }
    /// <summary>Recipients. Comma/semicolon-separated string OR a JSON array — both bind here.</summary>
    public string[] To         { get; set; } = Array.Empty<string>();
    /// <summary>Prepended to every subject so inbox filters can catch them.</summary>
    public string SubjectPrefix { get; set; } = "[NetFirewall]";
    public int TimeoutSeconds  { get; set; } = 15;
}

/// <summary>
/// Sends each notification as an email via System.Net.Mail (in-box .NET runtime —
/// no extra NuGet, honoring the no-new-dependency constraint). Fail-soft: a
/// broken relay logs a warning and returns; it never throws into the dispatcher.
/// </summary>
public sealed class SmtpNotifier : INotifier
{
    private readonly SmtpNotifierOptions _opts;
    private readonly ILogger<SmtpNotifier> _logger;

    public SmtpNotifier(IOptions<SmtpNotifierOptions> opts, ILogger<SmtpNotifier> logger)
    {
        _opts = opts.Value;
        _logger = logger;
    }

    public bool IsEnabled =>
        _opts.Enabled && !string.IsNullOrWhiteSpace(_opts.Host) && Recipients().Length > 0;

    public async Task NotifyAsync(NotificationMessage message, CancellationToken ct = default)
    {
        if (!IsEnabled) return;

        var from = _opts.From ?? _opts.Username;
        if (string.IsNullOrWhiteSpace(from))
        {
            _logger.LogWarning("SMTP notifier enabled but no From/Username configured — skipping email.");
            return;
        }

        var state = message.Resolved ? "RECOVERED" : message.Level.ToString().ToUpperInvariant();
        var subject = $"{_opts.SubjectPrefix} {state}: {message.Title}";
        var body = string.IsNullOrWhiteSpace(message.Body) ? message.Title : message.Body;

        using var mail = new MailMessage
        {
            From = new MailAddress(from),
            Subject = subject,
            Body = body,
            IsBodyHtml = false,
        };
        foreach (var to in Recipients()) mail.To.Add(to);

        using var client = new SmtpClient(_opts.Host!, _opts.Port)
        {
            EnableSsl = _opts.UseTls,
            Timeout = _opts.TimeoutSeconds * 1000,
        };
        if (!string.IsNullOrWhiteSpace(_opts.Username))
            client.Credentials = new NetworkCredential(_opts.Username, _opts.Password ?? string.Empty);

        try
        {
            await client.SendMailAsync(mail, ct);
            _logger.LogInformation("VPN notification emailed to {Count} recipient(s): {Subject}",
                Recipients().Length, subject);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to send notification email via {Host}:{Port}", _opts.Host, _opts.Port);
        }
    }

    // Accept either a real array (JSON config) or a single delimited string
    // (env-var config like "a@x.com,b@y.com") — split + trim either way.
    private string[] Recipients() =>
        _opts.To
            .SelectMany(t => t.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Where(t => t.Length > 0)
            .ToArray();
}
