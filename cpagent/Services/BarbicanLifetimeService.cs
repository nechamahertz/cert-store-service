namespace CpAgent.Services;

/// <summary>
/// Hosted service that manages Barbican lifecycle
/// Starts Barbican when the Agent starts
/// Stops Barbican when the Agent stops
/// </summary>
public class BarbicanLifetimeService : IHostedService
{
    private readonly ILogger<BarbicanLifetimeService> _logger;
    private readonly BarbicanManager _barbicanManager;

    public BarbicanLifetimeService(
        ILogger<BarbicanLifetimeService> logger,
        BarbicanManager barbicanManager)
    {
        _logger = logger;
        _barbicanManager = barbicanManager;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Agent starting - checking Barbican environment");
        
        try
        {
            // Check if Barbican environment exists
            var gunicornExecutable = Path.Combine(_barbicanManager.VirtualEnvPath, "bin", "gunicorn");
            if (!File.Exists(gunicornExecutable))
            {
                _logger.LogWarning(
                    "Barbican environment not found at {Path}. Run './scripts/setup-barbican-env.sh' to set up Barbican. " +
                    "Agent will start without Barbican for now.",
                    gunicornExecutable);
                return;
            }

            _logger.LogInformation("Launching Barbican...");
            await _barbicanManager.StartAsync(cancellationToken);
            _logger.LogInformation("Barbican launched successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start Barbican - continuing without it");
            // Don't throw - allow Agent to start even if Barbican fails
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Agent stopping - terminating Barbican");
        
        try
        {
            await _barbicanManager.StopAsync();
            _logger.LogInformation("Barbican terminated successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error stopping Barbican");
        }
    }
}
