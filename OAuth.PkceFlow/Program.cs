using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// CORS for Vite dev server
builder.Services.AddCors(options =>
{
    options.AddPolicy("spa", policy =>
    {
        policy.WithOrigins("http://localhost:5173")
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});

// Bind OAuth options
builder.Services.Configure<OAuthOptions>(builder.Configuration.GetSection("OAuth"));

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseCors("spa");

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", () =>
    {
        var forecast = Enumerable.Range(1, 5).Select(index =>
                new WeatherForecast
                (
                    DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                    Random.Shared.Next(-20, 55),
                    summaries[Random.Shared.Next(summaries.Length)]
                ))
            .ToArray();
        return forecast;
    })
    .WithName("GetWeatherForecast");

// ===== Minimal PKCE Authorization Server (demo-only) =====
var codeStore = new ConcurrentDictionary<string, AuthCode>(StringComparer.Ordinal);
var tokenStore = new ConcurrentDictionary<string, AccessToken>(StringComparer.Ordinal);

app.MapGet("/authorize", (
    string response_type,
    string client_id,
    string redirect_uri,
    string code_challenge,
    string code_challenge_method,
    string? state,
    IOptions<OAuthOptions> oauth
) =>
{
    // Basic validations
    if (!string.Equals(response_type, "code", StringComparison.Ordinal))
        return Results.BadRequest(new { error = "unsupported_response_type" });

    if (!string.Equals(code_challenge_method, "S256", StringComparison.Ordinal))
        return Results.BadRequest(new { error = "invalid_request", error_description = "code_challenge_method must be S256" });

    var cfg = oauth.Value;
    var client = cfg.Clients.FirstOrDefault(c => string.Equals(c.ClientId, client_id, StringComparison.Ordinal));
    if (client is null)
        return Results.BadRequest(new { error = "unauthorized_client" });

    if (!client.RedirectUris.Contains(redirect_uri, StringComparer.Ordinal))
        return Results.BadRequest(new { error = "invalid_request", error_description = "redirect_uri not allowed" });

    // Auto-approve user (no login page in demo)
    var code = PkceDemoHelpers.CreateHandle(32);
    var expiresAt = DateTimeOffset.UtcNow.AddSeconds(cfg.AuthorizationCodeLifetimeSeconds > 0 ? cfg.AuthorizationCodeLifetimeSeconds : 300);

    codeStore[code] = new AuthCode
    {
        ClientId = client_id,
        RedirectUri = redirect_uri,
        CodeChallenge = code_challenge,
        ExpiresAt = expiresAt,
        State = state
    };

    var redirect = PkceDemoHelpers.AppendQuery(redirect_uri, new Dictionary<string, string?>
    {
        ["code"] = code,
        ["state"] = state
    });

    return Results.Redirect(redirect);
});

app.MapPost("/token", async (HttpContext ctx, IOptions<OAuthOptions> oauth) =>
{
    if (!ctx.Request.HasFormContentType)
        return Results.BadRequest(new { error = "invalid_request", error_description = "content-type must be application/x-www-form-urlencoded" });

    var form = await ctx.Request.ReadFormAsync();
    var grantType = form["grant_type"].ToString();
    var code = form["code"].ToString();
    var redirectUri = form["redirect_uri"].ToString();
    var clientId = form["client_id"].ToString();
    var codeVerifier = form["code_verifier"].ToString();

    if (!string.Equals(grantType, "authorization_code", StringComparison.Ordinal))
        return Results.BadRequest(new { error = "unsupported_grant_type" });

    if (string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(redirectUri) || string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(codeVerifier))
        return Results.BadRequest(new { error = "invalid_request" });

    // Validate client and redirectUri
    var cfg = oauth.Value;
    var client = cfg.Clients.FirstOrDefault(c => string.Equals(c.ClientId, clientId, StringComparison.Ordinal));
    if (client is null)
        return Results.BadRequest(new { error = "unauthorized_client" });
    if (!client.RedirectUris.Contains(redirectUri, StringComparer.Ordinal))
        return Results.BadRequest(new { error = "invalid_grant", error_description = "redirect_uri mismatch" });

    if (!codeStore.TryRemove(code, out var authCode))
        return Results.BadRequest(new { error = "invalid_grant", error_description = "code not found or already used" });

    if (!string.Equals(authCode.ClientId, clientId, StringComparison.Ordinal) || !string.Equals(authCode.RedirectUri, redirectUri, StringComparison.Ordinal))
        return Results.BadRequest(new { error = "invalid_grant" });

    if (authCode.ExpiresAt < DateTimeOffset.UtcNow)
        return Results.BadRequest(new { error = "invalid_grant", error_description = "code expired" });

    // Verify PKCE
    var computed = PkceDemoHelpers.ComputeCodeChallenge(codeVerifier);
    if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(computed), Encoding.ASCII.GetBytes(authCode.CodeChallenge)))
        return Results.BadRequest(new { error = "invalid_grant", error_description = "code_verifier mismatch" });

    // Issue access token (opaque demo token)
    var accessToken = PkceDemoHelpers.Base64Url(RandomNumberGenerator.GetBytes(32));
    var tok = new AccessToken
    {
        Token = accessToken,
        ClientId = clientId,
        ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(cfg.AccessTokenLifetimeSeconds > 0 ? cfg.AccessTokenLifetimeSeconds : 3600)
    };
    tokenStore[accessToken] = tok;

    return Results.Json(new
    {
        access_token = accessToken,
        token_type = "Bearer",
        expires_in = (int)(tok.ExpiresAt - DateTimeOffset.UtcNow).TotalSeconds
    });
});

app.MapGet("/me", (HttpContext ctx) =>
{
    var token = PkceDemoHelpers.GetBearerToken(ctx.Request.Headers.Authorization);
    if (string.IsNullOrEmpty(token))
        return Results.Unauthorized();

    if (!tokenStore.TryGetValue(token!, out var at) || at.ExpiresAt <= DateTimeOffset.UtcNow)
        return Results.Unauthorized();

    // Demo profile
    return Results.Ok(new
    {
        sub = "demo-user",
        name = "Demo User",
        client_id = at.ClientId,
        expires_at = at.ExpiresAt
    });
});

app.Run();

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}

// ===== Simple models =====
class OAuthOptions
{
    public List<ClientConfig> Clients { get; set; } = new();
    public int AuthorizationCodeLifetimeSeconds { get; set; } = 300;
    public int AccessTokenLifetimeSeconds { get; set; } = 3600;
}

class ClientConfig
{
    public string ClientId { get; set; } = string.Empty;
    public List<string> RedirectUris { get; set; } = new();
}

class AuthCode
{
    public string ClientId { get; set; } = string.Empty;
    public string RedirectUri { get; set; } = string.Empty;
    public string CodeChallenge { get; set; } = string.Empty;
    public DateTimeOffset ExpiresAt { get; set; }
    public string? State { get; set; }
}

class AccessToken
{
    public string Token { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public DateTimeOffset ExpiresAt { get; set; }
}

// ===== Helpers moved to a dedicated static class =====
static class PkceDemoHelpers
{
    public static string AppendQuery(string url, IDictionary<string, string?> query)
    {
        var hasQuery = url.Contains('?');
        var sb = new StringBuilder(url);
        foreach (var kv in query)
        {
            if (kv.Value is null) continue;
            sb.Append(hasQuery ? '&' : '?');
            hasQuery = true;
            sb.Append(Uri.EscapeDataString(kv.Key));
            sb.Append('=');
            sb.Append(Uri.EscapeDataString(kv.Value));
        }
        return sb.ToString();
    }

    public static string CreateHandle(int bytes)
    {
        return Base64Url(RandomNumberGenerator.GetBytes(bytes));
    }

    public static string ComputeCodeChallenge(string codeVerifier)
    {
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
        return Base64Url(hash);
    }

    public static string Base64Url(byte[] data)
    {
        return Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    public static string? GetBearerToken(string? authHeader)
    {
        if (string.IsNullOrWhiteSpace(authHeader)) return null;
        const string prefix = "Bearer ";
        if (!authHeader.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return null;
        return authHeader.Substring(prefix.Length).Trim();
    }
}
