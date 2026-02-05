using System.Diagnostics;
using System.Runtime.InteropServices;
using CpAgent.Security;
using Microsoft.Extensions.Logging;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System;

namespace CpAgent.Services;

/// <summary>
/// Manages the Barbican process lifecycle with advanced hermetic isolation.
/// Implements Linux namespaces for network and filesystem sandboxing,
/// while providing explicit vTPM device mapping for secure key operations.
/// </summary>
public class BarbicanManager : IDisposable
{
    private readonly ILogger<BarbicanManager> _logger;
    private readonly IConfiguration _configuration;
    private readonly ILoggerFactory _loggerFactory;
    private Process? _barbicanProcess;
    private readonly SemaphoreSlim _semaphore = new(1, 1);
    private bool _disposed = false;
    private bool _tmpfsMounted = false;
    private SecureSocketGateway? _gateway;
    private CancellationTokenSource _cts = new CancellationTokenSource();
    private Task? _healthCheckTask;

    public string SocketPath { get; }
    public string InternalSocketPath { get; }
    public string SocketDirectory { get; }
    public string VirtualEnvPath { get; }
    public string ConfigPath { get; }
    public string LogPath { get; }
    public bool UseNamespaceIsolation { get; }
    public bool UseSecureGateway { get; }

    public BarbicanManager(
        ILogger<BarbicanManager> logger,
        IConfiguration configuration,
        ILoggerFactory loggerFactory)
    {
        _logger = logger;
        _configuration = configuration;
        _loggerFactory = loggerFactory;

        // Improved: Validate configuration values
        SocketDirectory = ValidateConfigPath(_configuration["Barbican:SocketDirectory"] ?? "/tmp/cpagent-hermetic", "SocketDirectory");
        SocketPath = Path.Combine(SocketDirectory, "barbican-public.sock");
        InternalSocketPath = Path.Combine(SocketDirectory, "barbican-internal.sock");
        VirtualEnvPath = ValidateConfigPath(_configuration["Barbican:VirtualEnvPath"] ?? "./barbican-env", "VirtualEnvPath");
        ConfigPath = ValidateConfigPath(_configuration["Barbican:ConfigPath"] ?? "./barbican-config", "ConfigPath");
        LogPath = ValidateConfigPath(_configuration["Barbican:LogPath"] ?? "./logs/barbican.log", "LogPath");

        // Enforce internal-only mode: always use namespace isolation and secure gateway
        UseNamespaceIsolation = true;
        UseSecureGateway = true;

        _logger.LogInformation(
            "BarbicanManager initialized. Public Socket: {PublicSocket}, " +
            "Internal Socket: {InternalSocket}, Gateway: {UseGateway}, Namespace Isolation: {UseNamespace}",
            SocketPath, InternalSocketPath, UseSecureGateway, UseNamespaceIsolation);
    }

    private string ValidateConfigPath(string path, string key)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException($"Configuration value for {key} cannot be empty.");
        }
        if (!Path.IsPathFullyQualified(path))
        {
            path = Path.GetFullPath(path);
        }
        return path;
    }

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        await _semaphore.WaitAsync(cancellationToken);
        try
        {
            if (_barbicanProcess != null && !_barbicanProcess.HasExited)
            {
                _logger.LogWarning("Barbican is already running");
                return;
            }

            if (!OperatingSystem.IsLinux())
            {
                throw new PlatformNotSupportedException("Hermetic isolation is only supported on Linux");
            }

            // Improved: Check kernel version for unshare support
            if (!CheckKernelVersion())
            {
                throw new PlatformNotSupportedException("Kernel version too old for namespace isolation (requires >= 2.6.23)");
            }

            await PrepareSecureSocketDirectoryAsync();
            CleanupStaleSocketsIfAny();

            var logDir = Path.GetDirectoryName(LogPath);
            if (!string.IsNullOrEmpty(logDir) && !Directory.Exists(logDir))
            {
                Directory.CreateDirectory(logDir);
            }

            if (UseSecureGateway)
            {
                _gateway = new SecureSocketGateway(
                    _loggerFactory.CreateLogger<SecureSocketGateway>(),
                    SocketPath,
                    InternalSocketPath);

                await _gateway.StartAsync(cancellationToken);
                _logger.LogInformation("🛡️ SecureSocketGateway started - PID validation active");
            }

            if (UseNamespaceIsolation)
            {
                await StartWithNamespaceIsolationAsync(cancellationToken);
            }
            else
            {
                await StartStandardAsync(cancellationToken);
            }

            _logger.LogInformation("Waiting for internal socket...");
            await WaitForInternalSocketAsync(cancellationToken);
            _logger.LogInformation("Internal socket found. Setting permissions...");
            SetInternalSocketPermissionsNative();
            _logger.LogInformation("Permissions set. Starting health check...");

            // Improved: Start health check loop
            _cts = new CancellationTokenSource();
            _healthCheckTask = HealthCheckLoopAsync(_cts.Token);

            _logger.LogInformation("✅ Barbican security system fully operational with vTPM passthrough.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start Barbican");
            await CleanupAsync();
            throw;
        }
        finally
        {
            _semaphore.Release();
        }
    }

    private bool CheckKernelVersion()
    {
        // Simple check: parse uname -r
        var unameProcess = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "uname",
                Arguments = "-r",
                RedirectStandardOutput = true,
                UseShellExecute = false
            }
        };
        unameProcess.Start();
        var versionStr = unameProcess.StandardOutput.ReadToEnd().Trim();
        unameProcess.WaitForExit();

        if (Version.TryParse(versionStr.Split('-')[0], out var version) && version >= new Version(2, 6, 23))
        {
            return true;
        }
        return false;
    }

    private async Task HealthCheckLoopAsync(CancellationToken ct)
    {
        // Yield to allow StartAsync to complete and release the semaphore
        await Task.Yield();

        try
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var status = GetStatus();
                    // Fixed: Use dynamic or cast to avoid pattern matching issues in older C# versions
                    dynamic? dynStatus = status;
                    if (dynStatus != null && dynStatus.state == "exited")
                    {
                        _logger.LogWarning("Health check failed: Barbican exited. Attempting restart.");
                        await RestartAsync(ct);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogError(ex, "Health check error");
                }
                await Task.Delay(TimeSpan.FromSeconds(30), ct);
            }
        }
        catch (OperationCanceledException)
        {
            // Expected on shutdown
        }
    }

    private async Task RestartAsync(CancellationToken ct)
    {
        await StopAsync();
        await StartAsync(ct);
    }

    private async Task StartWithNamespaceIsolationAsync(CancellationToken cancellationToken)
    {
        var gunicornPath = Path.Combine(VirtualEnvPath, "bin", "gunicorn");
        var scriptPath = CreateNamespaceWrapperScript(gunicornPath);

        var startInfo = new ProcessStartInfo
        {
            FileName = "sudo",
            Arguments = $"-E {scriptPath}",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = VirtualEnvPath,
            Environment =
            {
                ["PYTHONUNBUFFERED"] = "1",
                ["PATH"] = $"{Path.Combine(VirtualEnvPath, "bin")}:{Environment.GetEnvironmentVariable("PATH")}",
                ["BARBICAN_SOCKET_PATH"] = UseSecureGateway ? InternalSocketPath : SocketPath,
                ["TPM2TOOLS_TCTI"] = "device:/dev/tpmrm0"
            }
        };

        _barbicanProcess = new Process { StartInfo = startInfo };
        _barbicanProcess.OutputDataReceived += (sender, e) => { if (!string.IsNullOrEmpty(e.Data)) _logger.LogInformation("[Barbican] {Output}", e.Data); };
        _barbicanProcess.ErrorDataReceived += (s, e) => {
            if (!string.IsNullOrEmpty(e.Data)) {
                if (e.Data.Contains("[INFO]") || e.Data.Contains("Worker exiting") || e.Data.Contains("Handling signal")) {
                    _logger.LogInformation($"[Barbican] {e.Data}");
                } 
                else if (e.Data.Contains("[ERROR]") && !e.Data.Contains("SIGHUP")) {
                    _logger.LogError($"[Barbican] {e.Data}");
                }
                else {
                    _logger.LogDebug($"[Barbican] {e.Data}");
                }
            }
        };
        // Improved: Retry start up to 3 times
        bool started = false;
        int retries = 3;
        while (!started && retries > 0)
        {
            try
            {
                _barbicanProcess.Start();
                _barbicanProcess.BeginOutputReadLine();
                _barbicanProcess.BeginErrorReadLine();
                started = true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to start process, retrying...");
                retries--;
                await Task.Delay(1000, cancellationToken);
            }
        }
        if (!started)
        {
            throw new InvalidOperationException("Failed to start Barbican process after retries.");
        }
    }

    private string CreateNamespaceWrapperScript(string gunicornPath)
    {
        var socketToUse = UseSecureGateway ? InternalSocketPath : SocketPath;
        var scriptPath = Path.Combine("/tmp", $"barbican-ns-{Guid.NewGuid():N}.sh");
        
        var absoluteVirtualEnvPath = Path.GetFullPath(VirtualEnvPath);
        var absoluteGunicornPath = Path.GetFullPath(gunicornPath);
        var absolutePathToProject = Path.GetFullPath(Path.Combine(absoluteVirtualEnvPath, ".."));

        // Improved: Use StringBuilder for script to avoid interpolation issues
        var scriptBuilder = new System.Text.StringBuilder();
        scriptBuilder.AppendLine("#!/bin/bash");
        scriptBuilder.AppendLine("set -e");
        scriptBuilder.AppendLine("");
        scriptBuilder.AppendLine("# Validate host device");
        scriptBuilder.AppendLine("if [ ! -e /dev/tpmrm0 ]; then");
        scriptBuilder.AppendLine("    echo 'FATAL: /dev/tpmrm0 not found' >&2");
        scriptBuilder.AppendLine("    exit 1");
        scriptBuilder.AppendLine("fi");
        scriptBuilder.AppendLine("");
        scriptBuilder.AppendLine("# --mount: Isolation for filesystems");
        scriptBuilder.AppendLine("# --net: Isolation for network");
        scriptBuilder.AppendLine("exec /usr/bin/unshare --net --mount /bin/bash -c \"");
        scriptBuilder.AppendLine("    # Bind entire host /dev to a temp path BEFORE overwriting /dev");
        scriptBuilder.AppendLine("    mkdir -p /tmp/host-dev");
        scriptBuilder.AppendLine("    mount --bind /dev /tmp/host-dev");
        scriptBuilder.AppendLine("");
        scriptBuilder.AppendLine("    # 1. Create a minimal tmpfs for /dev to hide the host's devices");
        scriptBuilder.AppendLine("    mount -t tmpfs -o mode=755 tmpfs /dev");
        scriptBuilder.AppendLine("    ");
        scriptBuilder.AppendLine("    # 2. Re-expose only what is absolutely necessary");
        scriptBuilder.AppendLine("    touch /dev/tpmrm0");
        scriptBuilder.AppendLine("    mount --bind /tmp/host-dev/tpmrm0 /dev/tpmrm0");
        scriptBuilder.AppendLine("    ");
        scriptBuilder.AppendLine("    # Essential for many Python apps/libraries");
        scriptBuilder.AppendLine("    touch /dev/null /dev/random /dev/urandom");
        scriptBuilder.AppendLine("    mount --bind /tmp/host-dev/null /dev/null");
        scriptBuilder.AppendLine("    mount --bind /tmp/host-dev/random /dev/random");
        scriptBuilder.AppendLine("    mount --bind /tmp/host-dev/urandom /dev/urandom");
        scriptBuilder.AppendLine("");
        scriptBuilder.AppendLine("    # Cleanup temp bind");
        scriptBuilder.AppendLine("    umount /tmp/host-dev");
        scriptBuilder.AppendLine("    rmdir /tmp/host-dev");
        scriptBuilder.AppendLine("");
        scriptBuilder.AppendLine("    # Set parent death signal");
        scriptBuilder.AppendLine("    python3 -c 'import ctypes; libc = ctypes.CDLL(\"libc.so.6\"); libc.prctl(1, 9, 0, 0, 0)'");
        scriptBuilder.AppendLine("    ");
        scriptBuilder.AppendLine($"    CONF_DIR='{absolutePathToProject}/barbican-config'");
        scriptBuilder.AppendLine("    CONF_FILE=\"$CONF_DIR/barbican.conf\"");
        scriptBuilder.AppendLine("    PASTE_FILE=\"$CONF_DIR/barbican-api-paste.ini\"");
        scriptBuilder.AppendLine("    ");
        scriptBuilder.AppendLine($"    cd {absoluteVirtualEnvPath}");
        scriptBuilder.AppendLine("    echo '[Wrapper] Barbican started with Restricted /dev and No-Network.'");
        scriptBuilder.AppendLine("    ");
        scriptBuilder.AppendLine("    LOCAL_CONF=\"$CONF_FILE\"");
        scriptBuilder.AppendLine("");
        scriptBuilder.AppendLine("    export BARBICAN_SETTINGS=\"$CONF_FILE\"");
        scriptBuilder.AppendLine("    export OSLO_CONFIG_FILE=\"$CONF_FILE\"");
        scriptBuilder.AppendLine("    export BARBICAN_API_PASTE_CONFIG=\"$PASTE_FILE\"");
        scriptBuilder.AppendLine("");
        scriptBuilder.AppendLine($"    exec {absoluteGunicornPath} 'barbican.api.app:get_api_wsgi_script()' \\");
        scriptBuilder.AppendLine($"        --bind unix:{socketToUse} \\");
        scriptBuilder.AppendLine("        --workers 2 \\");
        scriptBuilder.AppendLine("        --timeout 120 \\");
        scriptBuilder.AppendLine("        --env BARBICAN_SETTINGS=\"$LOCAL_CONF\" \\");
        scriptBuilder.AppendLine("        --env OSLO_CONFIG_FILE=\"$LOCAL_CONF\"");
        scriptBuilder.AppendLine("\"");

        var scriptContent = scriptBuilder.ToString();
        File.WriteAllText(scriptPath, scriptContent);
        if (OperatingSystem.IsLinux())
        {
            LinuxNativeInterop.SetFilePermissions(scriptPath, 0x1C0); // 0700
        }

        return scriptPath;
    }

    private async Task StartStandardAsync(CancellationToken cancellationToken)
    {
        var gunicornPath = Path.Combine(VirtualEnvPath, "bin", "gunicorn");
        var socketToUse = UseSecureGateway ? InternalSocketPath : SocketPath;

        var startInfo = new ProcessStartInfo
        {
            FileName = gunicornPath,
            Arguments = $"\"barbican.api.app:get_api_wsgi_script()\" --bind unix:{socketToUse} --workers 2 --timeout 120",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = VirtualEnvPath
        };

        _barbicanProcess = new Process { StartInfo = startInfo };
        // Similar retry logic
        bool started = false;
        int retries = 3;
        while (!started && retries > 0)
        {
            try
            {
                _barbicanProcess.Start();
                started = true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to start standard process, retrying...");
                retries--;
                await Task.Delay(1000, cancellationToken);
            }
        }
        if (!started)
        {
            throw new InvalidOperationException("Failed to start Barbican process after retries.");
        }
    }

    private async Task PrepareSecureSocketDirectoryAsync()
    {
        if (!Directory.Exists(SocketDirectory))
        {
            Directory.CreateDirectory(SocketDirectory);
        }
        try
        {
            LinuxNativeInterop.SetFilePermissions(SocketDirectory, 0x1C0); // 0700
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not set permissions for {Directory}. Ignoring...", SocketDirectory);
        }
    }

    private void CleanupStaleSocketsIfAny()
    {
        try
        {
            if (File.Exists(SocketPath)) File.Delete(SocketPath);
            if (File.Exists(InternalSocketPath)) File.Delete(InternalSocketPath);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to clean stale sockets");
        }
    }

    private async Task CleanupAsync()
    {
        CleanupStaleSocketsIfAny();
        var scripts = Directory.GetFiles("/tmp", "barbican-ns-*.sh");
        foreach (var s in scripts)
        {
            try { File.Delete(s); } catch (Exception ex) { _logger.LogWarning(ex, "Failed to delete script {Script}", s); }
        }
        if (_tmpfsMounted)
        {
            try { LinuxNativeInterop.umount(SocketDirectory); } catch (Exception ex) { _logger.LogWarning(ex, "Failed to umount"); }
        }
        await Task.CompletedTask;
    }

    private async Task WaitForInternalSocketAsync(CancellationToken cancellationToken)
    {
        var maxWaitTime = TimeSpan.FromSeconds(30);
        var startTime = DateTime.UtcNow;
        var socketToWait = UseSecureGateway ? InternalSocketPath : SocketPath;

        while (DateTime.UtcNow - startTime < maxWaitTime)
        {
            if (File.Exists(socketToWait)) return;
            await Task.Delay(100, cancellationToken);
        }
        throw new TimeoutException($"Socket was not created: {socketToWait}");
    }

    private void SetInternalSocketPermissionsNative()
    {
        var socketToSecure = UseSecureGateway ? InternalSocketPath : SocketPath;
        if (File.Exists(socketToSecure) && OperatingSystem.IsLinux())
        {
            try
            {
                LinuxNativeInterop.SetFilePermissions(socketToSecure, 0x180); // 0600
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not set permissions for {Socket}. Ignoring...", socketToSecure);
            }
        }
    }

    public object GetStatus()
    {
        _semaphore.Wait();
        try
        {
            var gatewayStatus = _gateway != null ? "running" : "stopped";

            if (_barbicanProcess == null)
            {
                return new { state = "not-started", gatewayStatus = gatewayStatus };
            }

            if (_barbicanProcess.HasExited)
            {
                return new
                {
                    state = "exited",
                    exitCode = _barbicanProcess.ExitCode,
                    gatewayStatus = gatewayStatus
                };
            }

            return new
            {
                state = "running",
                processId = _barbicanProcess.Id,
                startTime = _barbicanProcess.StartTime,
                publicSocketExists = File.Exists(SocketPath),
                internalSocketExists = File.Exists(InternalSocketPath),
                gatewayStatus = gatewayStatus,
                namespaceIsolation = UseNamespaceIsolation
            };
        }
        finally
        {
            _semaphore.Release();
        }
    }

    public async Task StopAsync()
    {
        await _semaphore.WaitAsync();
        try
        {
            if (_cts != null && !_cts.IsCancellationRequested)
            {
                _cts.Cancel();
                if (_healthCheckTask != null)
                {
                    await _healthCheckTask;
                }
            }

            if (_gateway != null)
            {
                await _gateway.StopAsync();
                _gateway.Dispose();
                _gateway = null;
            }

            if (_barbicanProcess != null && !_barbicanProcess.HasExited)
            {
                // Fixed: Proper graceful shutdown with SIGTERM on Linux
                if (OperatingSystem.IsLinux())
                {
                    LinuxNativeInterop.kill(_barbicanProcess.Id, LinuxNativeInterop.SIGTERM);
                }
                else
                {
                    _barbicanProcess.Kill(false); // On non-Linux, use standard Kill without tree
                }

                // Fixed: Use CancellationTokenSource for timeout in .NET 8
                using var timeoutCts = new CancellationTokenSource(3000); // Wait 3 seconds
                try
                {
                    await _barbicanProcess.WaitForExitAsync(timeoutCts.Token);
                }
                catch (OperationCanceledException)
                {
                    _logger.LogWarning("Graceful shutdown timed out, forcing kill");
                    try 
                    {
                        _barbicanProcess.Kill(true); // Kill entire tree
                    }
                    catch (Exception kParEx)
                    {
                         _logger.LogError(kParEx, "Failed to force kill process tree.");
                    }

                    using var forceTimeoutCts = new CancellationTokenSource(2000); // Wait 2 seconds for kill
                    try
                    {
                        await _barbicanProcess.WaitForExitAsync(forceTimeoutCts.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        _logger.LogError("Force kill timed out. Process might be zombie.");
                    }
                }
            }

            await CleanupAsync();
        }
        finally
        {
            _barbicanProcess?.Dispose();
            _barbicanProcess = null;
            _semaphore.Release();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        StopAsync().GetAwaiter().GetResult();
        _semaphore.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}