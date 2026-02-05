using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace CpAgent.Services;

public class BarbicanClient
{
    private readonly ILogger<BarbicanClient> _logger;
    private readonly BarbicanManager _barbicanManager;
    private readonly HttpClient _httpClient;

    public BarbicanClient(ILogger<BarbicanClient> logger, BarbicanManager barbicanManager)
    {
        
        _logger = logger;
        _barbicanManager = barbicanManager;
        
        // Create HttpClient with Unix socket handler
        var socketsHandler = new SocketsHttpHandler
        {
            ConnectCallback = async (context, cancellationToken) =>
            {
                var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                var endpoint = new UnixDomainSocketEndPoint(_barbicanManager.SocketPath);
                await socket.ConnectAsync(endpoint, cancellationToken);
                return new NetworkStream(socket, ownsSocket: true);
            }
        };
        
        _httpClient = new HttpClient(socketsHandler)
        {
            BaseAddress = new Uri("http://localhost"),
            Timeout = TimeSpan.FromSeconds(10)
        };
        
        // Add required Barbican headers
        _httpClient.DefaultRequestHeaders.Add("X-Project-Id", "cpagent-project");
        _httpClient.DefaultRequestHeaders.Add("X-Roles", "admin");
    }

    /// <summary>
    /// Create a new secret in Barbican
    /// </summary>
    public async Task<string> CreateSecretAsync(string name, string payload)
    {
        var requestBody = new
        {
            name,
            payload,
            payload_content_type = "text/plain"
        };

        var content = new StringContent(
            JsonSerializer.Serialize(requestBody),
            Encoding.UTF8,
            "application/json");

        var response = await _httpClient.PostAsync("/v1/secrets", content);
        return await response.Content.ReadAsStringAsync();
    }

    /// <summary>
    /// Get secret metadata
    /// </summary>
    public async Task<string> GetSecretAsync(string secretId)
    {
        var response = await _httpClient.GetAsync($"/v1/secrets/{secretId}");
        return await response.Content.ReadAsStringAsync();
    }

    /// <summary>
    /// Get secret payload/value
    /// </summary>
    public async Task<string> GetSecretPayloadAsync(string secretId)
    {
        var response = await _httpClient.GetAsync($"/v1/secrets/{secretId}/payload");
        return await response.Content.ReadAsStringAsync();
    }

    /// <summary>
    /// List all secrets
    /// </summary>
    public async Task<string> ListSecretsAsync()
    {
        var response = await _httpClient.GetAsync("/v1/secrets");
        return await response.Content.ReadAsStringAsync();
    }

    /// <summary>
    /// Delete a secret
    /// </summary>
    public async Task<string> DeleteSecretAsync(string secretId)
    {
        var response = await _httpClient.DeleteAsync($"/v1/secrets/{secretId}");
        return await response.Content.ReadAsStringAsync();
    }
}
