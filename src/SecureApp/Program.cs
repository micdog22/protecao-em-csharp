using System;
using System.IO;
using System.Text.Json;
using SecureApp.Guard;

namespace SecureApp;

public sealed class AppConfig
{
    public bool EnforceSignature { get; set; } = false;
    public string[] AllowedPublisherCn { get; set; } = Array.Empty<string>();
}

internal static class Program
{
    private static int Main(string[] args)
    {
        Console.Title = "SecureApp — Template C# Seguro";
        var exePath = Environment.ProcessPath ?? System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName!;
        var cfgPath = Path.Combine(AppContext.BaseDirectory, "secure.json");
        var cfg = LoadConfig(cfgPath);

        var res = SignatureVerifier.Verify(exePath, cfg.AllowedPublisherCn);
        if (cfg.EnforceSignature)
        {
            if (!res.Success)
            {
                Console.Error.WriteLine($"[ERRO] Assinatura inválida ou ausente: {res.Message} (0x{res.StatusCode:X8})");
                return 1;
            }
            if (cfg.AllowedPublisherCn.Length > 0 && !res.MatchesAllowedPublisher)
            {
                Console.Error.WriteLine("[ERRO] CN do emissor não está na lista permitida.");
                return 1;
            }
        }
        else
        {
            if (!res.Success)
            {
                Console.WriteLine($"[AVISO] Execução sem assinatura válida: {res.Message}");
            }
            else
            {
                Console.WriteLine($"[OK] Assinatura válida. Sujeito: {res.Subject}");
                if (cfg.AllowedPublisherCn.Length > 0)
                    Console.WriteLine($"[INFO] CN permitido? {res.MatchesAllowedPublisher}");
            }
        }

        // === Sua aplicação aqui ===
        Console.WriteLine("Hello, world! Projeto base seguro carregado com sucesso.");
        return 0;
    }

    private static AppConfig LoadConfig(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                var json = File.ReadAllText(path);
                var cfg = JsonSerializer.Deserialize<AppConfig>(json, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
                return cfg ?? new AppConfig();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[AVISO] Falha ao carregar secure.json: {ex.Message}");
        }
        return new AppConfig();
    }
}
