using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace CpAgent.Controllers;

[ApiController]
[Route("api/[controller]")]
public class SecretsController : ControllerBase
{
    private readonly ILogger<SecretsController> _logger;
    private readonly Services.BarbicanClient _barbicanClient;

    public SecretsController(
        ILogger<SecretsController> logger,
        Services.BarbicanClient barbicanClient)
    {
        _logger = logger;
        _barbicanClient = barbicanClient;
    }

    /// <summary>
    /// Create a new secret
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> CreateSecret([FromBody] CreateSecretRequest request)
    {
        try
        {
            _logger.LogInformation("Creating secret: {Name}", request.Name);
            
            // Convert payload to base64 if not already
            var payloadBase64 = request.Payload;
            if (!request.IsBase64)
            {
                payloadBase64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(request.Payload));
            }

            var response = await _barbicanClient.CreateSecretAsync(
                request.Name,
                payloadBase64
            );

            return Ok(new { 
                success = true,
                message = "Secret created successfully",
                response = JsonSerializer.Deserialize<object>(response)
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create secret");
            return StatusCode(500, new { 
                success = false, 
                error = ex.Message 
            });
        }
    }

    /// <summary>
    /// Get secret metadata
    /// </summary>
    [HttpGet("{secretId}")]
    public async Task<IActionResult> GetSecret(string secretId)
    {
        try
        {
            _logger.LogInformation("Getting secret: {SecretId}", secretId);
            var response = await _barbicanClient.GetSecretAsync(secretId);
            
            return Ok(new {
                success = true,
                data = JsonSerializer.Deserialize<object>(response)
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get secret");
            return StatusCode(500, new { 
                success = false, 
                error = ex.Message 
            });
        }
    }

    /// <summary>
    /// Get secret payload (the actual secret value)
    /// </summary>
    [HttpGet("{secretId}/payload")]
    public async Task<IActionResult> GetSecretPayload(string secretId)
    {
        try
        {
            _logger.LogInformation("Getting secret payload: {SecretId}", secretId);
            var response = await _barbicanClient.GetSecretPayloadAsync(secretId);
            
            // Try to decode base64 if it's text
            try
            {
                var decoded = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(response));
                return Ok(new {
                    success = true,
                    payload = decoded,
                    payloadBase64 = response
                });
            }
            catch
            {
                return Ok(new {
                    success = true,
                    payload = response
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get secret payload");
            return StatusCode(500, new { 
                success = false, 
                error = ex.Message 
            });
        }
    }

    /// <summary>
    /// List all secrets
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> ListSecrets()
    {
        try
        {
            _logger.LogInformation("Listing secrets");
            var response = await _barbicanClient.ListSecretsAsync();
            
            return Ok(new {
                success = true,
                data = JsonSerializer.Deserialize<object>(response)
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to list secrets");
            return StatusCode(500, new { 
                success = false, 
                error = ex.Message 
            });
        }
    }

    /// <summary>
    /// Delete a secret
    /// </summary>
    [HttpDelete("{secretId}")]
    public async Task<IActionResult> DeleteSecret(string secretId)
    {
        try
        {
            _logger.LogInformation("Deleting secret: {SecretId}", secretId);
            await _barbicanClient.DeleteSecretAsync(secretId);
            
            return Ok(new {
                success = true,
                message = "Secret deleted successfully"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to delete secret");
            return StatusCode(500, new { 
                success = false, 
                error = ex.Message 
            });
        }
    }
}

public class CreateSecretRequest
{
    public string Name { get; set; } = string.Empty;
    public string Payload { get; set; } = string.Empty;
    public string? ContentType { get; set; }
    public bool IsBase64 { get; set; } = false;
}
