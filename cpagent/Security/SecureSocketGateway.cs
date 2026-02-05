using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using System;
using System.Threading;

namespace CpAgent.Security;

/// <summary>
/// Secure Socket Gateway with Linux Peer Credential Validation
/// 
/// This gateway provides hermetic isolation by:
/// 1. Listening on a public Unix Domain Socket
/// 2. Validating connecting process credentials via SO_PEERCRED
/// 3. Only allowing connections from the parent .NET process (PID validation)
/// 4. Transparently proxying validated traffic to the internal Barbican socket
/// 
/// Security Guarantee: Even if an attacker has filesystem access to the public socket,
/// they CANNOT connect unless they are the exact process (PID match).
/// </summary>
public class SecureSocketGateway : IDisposable
{
    private readonly ILogger<SecureSocketGateway> _logger;
    private readonly string _publicSocketPath;
    private readonly string _internalSocketPath;
    private readonly int _ownerProcessId;
    private Socket? _listenerSocket;
    private CancellationTokenSource? _cancellationTokenSource;
    private Task? _acceptLoopTask;
    private bool _disposed;

    public SecureSocketGateway(
        ILogger<SecureSocketGateway> logger,
        string publicSocketPath,
        string internalSocketPath)
    {
        _logger = logger;
        _publicSocketPath = publicSocketPath;
        _internalSocketPath = internalSocketPath;
        _ownerProcessId = Environment.ProcessId;

        _logger.LogInformation(
            "SecureSocketGateway initialized. Owner PID: {OwnerPid}, Public: {PublicSocket}, Internal: {InternalSocket}",
            _ownerProcessId, _publicSocketPath, _internalSocketPath);
    }

    /// <summary>
    /// Start the gateway server
    /// </summary>
    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        if (_listenerSocket != null)
        {
            throw new InvalidOperationException("Gateway is already running");
        }

        // Ensure public socket doesn't already exist
        if (File.Exists(_publicSocketPath))
        {
            File.Delete(_publicSocketPath);
            _logger.LogInformation("Removed stale public socket: {PublicSocket}", _publicSocketPath);
        }

        // Create Unix domain socket listener
        var endpoint = new UnixDomainSocketEndPoint(_publicSocketPath);
        _listenerSocket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        _listenerSocket.Bind(endpoint);
        _listenerSocket.Listen(10);

        // Set permissions to owner-only (0600)
        LinuxNativeInterop.SetFilePermissions(_publicSocketPath, 0x180); // 0600 octal

        _logger.LogInformation("Gateway listening on {PublicSocket} (permissions: 0600)", _publicSocketPath);

        // Start accept loop
        _cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _acceptLoopTask = AcceptConnectionsAsync(_cancellationTokenSource.Token);

        await Task.CompletedTask;
    }

    /// <summary>
    /// Stop the gateway server
    /// </summary>
    public async Task StopAsync()
    {
        if (_cancellationTokenSource != null)
        {
            _cancellationTokenSource.Cancel();
            
            if (_acceptLoopTask != null)
            {
                try
                {
                    await _acceptLoopTask;
                }
                catch (OperationCanceledException)
                {
                    // Expected
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error during accept loop shutdown");
                }
            }
        }

        _listenerSocket?.Close();
        _listenerSocket?.Dispose();
        _listenerSocket = null;

        if (File.Exists(_publicSocketPath))
        {
            try { File.Delete(_publicSocketPath); } catch (Exception ex) { _logger.LogWarning(ex, "Failed to delete public socket"); }
        }

        _logger.LogInformation("Gateway stopped");
    }

    /// <summary>
    /// Main accept loop - waits for incoming connections
    /// </summary>
    private async Task AcceptConnectionsAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Gateway accept loop started");

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    var clientSocket = await _listenerSocket!.AcceptAsync(cancellationToken);
                    
                    // Handle each connection in a separate task
                    _ = Task.Run(() => HandleConnectionAsync(clientSocket, cancellationToken), cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.OperationAborted)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error accepting connection");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Accept loop terminated with error");
        }

        _logger.LogInformation("Gateway accept loop stopped");
    }

    /// <summary>
    /// Handle individual client connection with PID validation
    /// </summary>
    private async Task HandleConnectionAsync(Socket clientSocket, CancellationToken cancellationToken)
    {
        Socket? backendSocket = null;
        try
        {
            var credentials = GetPeerCredentials(clientSocket);

            if (credentials == null || credentials.Value.pid != _ownerProcessId)
            {
                _logger.LogWarning("Security Violation: Unauthorized PID {Pid}", credentials?.pid);
                clientSocket.LingerState = new LingerOption(true, 0); 
                clientSocket.Close();
                return;
            }

            // Apply hardware-level timeouts (in milliseconds)
            clientSocket.ReceiveTimeout = 2000; 
            clientSocket.SendTimeout = 2000;

            backendSocket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            // Improved: Retry connect up to 3 times
            bool connected = false;
            int retries = 3;
            while (!connected && retries > 0)
            {
                try
                {
                    await backendSocket.ConnectAsync(new UnixDomainSocketEndPoint(_internalSocketPath), cancellationToken);
                    connected = true;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to connect to internal socket, retrying...");
                    retries--;
                    await Task.Delay(500, cancellationToken);
                }
            }
            if (!connected)
            {
                throw new InvalidOperationException("Failed to connect to internal socket after retries.");
            }
            
            backendSocket.ReceiveTimeout = 2000;
            backendSocket.SendTimeout = 2000;

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            
            // Start proxying
            var clientToBackend = ProxyDataAsync(clientSocket, backendSocket, "C->B", cts.Token);
            var backendToClient = ProxyDataAsync(backendSocket, clientSocket, "B->C", cts.Token);

            await Task.WhenAny(clientToBackend, backendToClient);
            
            // If one side finishes or fails, immediately kill the other
            cts.Cancel(); 
        }
        catch (Exception ex)
        {
            _logger.LogDebug("Gateway session ended: {Message}", ex.Message);
        }
        finally
        {
            backendSocket?.Dispose();
            clientSocket.Dispose();
        }
    }

    /// <summary>
    /// Proxy data from source to destination socket
    /// </summary>
    private async Task ProxyDataAsync(Socket source, Socket destination, string direction, CancellationToken ct)
    {
        var buffer = new byte[8192];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                int bytesRead = await source.ReceiveAsync(buffer, SocketFlags.None, ct)
                                            .AsTask()
                                            .WaitAsync(TimeSpan.FromSeconds(2), ct);
                
                if (bytesRead == 0) break; 

                await destination.SendAsync(buffer.AsMemory(0, bytesRead), SocketFlags.None, ct);
            }
        }
        catch (TimeoutException)
        {
            _logger.LogWarning("Gateway Enforcement: Hard timeout reached for {Direction}. Dropping suspicious connection.", direction);
        }
        catch (OperationCanceledException)
        {
            // Normal cancellation
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
        {
            _logger.LogWarning("Socket timeout in {Direction}", direction);
        }
        catch (Exception ex)
        {
            _logger.LogDebug("Proxy {Direction} closed: {Message}", direction, ex.Message);
        }
        finally
        {
            source.Close();
            destination.Close();
        }
    }

    /// <summary>
    /// Retrieve peer credentials using SO_PEERCRED
    /// </summary>
    private LinuxNativeInterop.ucred? GetPeerCredentials(Socket socket)
    {
        try
        {
            var socketHandle = socket.Handle.ToInt32();
            return LinuxNativeInterop.GetPeerCredentials(socketHandle);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to retrieve peer credentials");
            return null;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        try
        {
            StopAsync().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during disposal");
        }
        finally
        {
            _cancellationTokenSource?.Dispose();
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }
}