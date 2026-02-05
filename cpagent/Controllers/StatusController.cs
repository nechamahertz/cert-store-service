using Microsoft.AspNetCore.Mvc;

namespace CpAgent.Controllers;

[ApiController]
[Route("api/[controller]")]
public class StatusController : ControllerBase
{
    private readonly ILogger<StatusController> _logger;
    private readonly Services.BarbicanManager _barbicanManager;

    public StatusController(
        ILogger<StatusController> logger,
        Services.BarbicanManager barbicanManager)
    {
        _logger = logger;
        _barbicanManager = barbicanManager;
    }

    /// <summary>
    /// Health check endpoint
    /// </summary>
    [HttpGet("health")]
    public IActionResult GetHealth()
    {
        var status = new
        {
            agent = "healthy",
            timestamp = DateTime.UtcNow,
            barbican = _barbicanManager.GetStatus()
        };

        return Ok(status);
    }

    /// <summary>
    /// Detailed status information
    /// </summary>
    [HttpGet]
    public IActionResult GetStatus()
    {
        var status = new
        {
            agent = new
            {
                version = "1.0.0",
                uptime = DateTime.UtcNow - System.Diagnostics.Process.GetCurrentProcess().StartTime.ToUniversalTime(),
                processId = System.Diagnostics.Process.GetCurrentProcess().Id
            },
            barbican = _barbicanManager.GetStatus(),
            isolation = new
            {
                socketPath = _barbicanManager.SocketPath,
                socketExists = System.IO.File.Exists(_barbicanManager.SocketPath),
                enforcement = "unix-socket-only"
            }
        };

        return Ok(status);
    }
}
