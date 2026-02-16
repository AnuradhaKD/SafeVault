using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using SafeVault.Api.Models;
using SafeVault.Api.Security;
using SafeVault.Core.InputValidation;
using SafeVault.Core.Security;
using SafeVault.Data.Users;

var builder = WebApplication.CreateBuilder(args);

// In-memory repository for tests/demos (no DB needed).
// Replace with MySqlUserRepository for real deployment (still SQLi-safe).
builder.Services.AddSingleton<IUserRepository, InMemoryUserRepository>();
builder.Services.AddSingleton<JwtTokenService>();

var jwtSvc = new JwtTokenService(builder.Configuration);
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o => o.TokenValidationParameters = jwtSvc.GetValidationParameters());

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", p => p.RequireRole("Admin"));
});

var app = builder.Build();

// Security headers (defense-in-depth)
app.UseMiddleware<SecurityHeadersMiddleware>();

app.UseAuthentication();
app.UseAuthorization();

// Demo store for user-generated content
var comments = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

// ---------- Auth ----------
app.MapPost("/auth/register", async (RegisterRequest model, IUserRepository repo) =>
{
    var (uOk, uErr, username) = InputValidator.ValidateUsername(model.Username);
    if (!uOk) return Results.BadRequest(new { error = uErr });

    var (eOk, eErr, email) = InputValidator.ValidateEmail(model.Email);
    if (!eOk) return Results.BadRequest(new { error = eErr });

    var (pOk, pErr, password) = InputValidator.ValidatePassword(model.Password);
    if (!pOk) return Results.BadRequest(new { error = pErr });

    var (rOk, rErr, role) = InputValidator.ValidateRole(model.Role);
    if (!rOk) return Results.BadRequest(new { error = rErr });

    var hash = PasswordHasher.Hash(password);

    try
    {
        var id = await repo.CreateUserAsync(username, email, hash, role);
        return Results.Created($"/users/{id}", new { userId = id, username, email, role });
    }
    catch (InvalidOperationException ex)
    {
        return Results.Conflict(new { error = ex.Message });
    }
});

app.MapPost("/auth/login", async (LoginRequest model, IUserRepository repo, JwtTokenService tokenService) =>
{
    var (uOk, uErr, username) = InputValidator.ValidateUsername(model.Username);
    if (!uOk) return Results.BadRequest(new { error = uErr });

    var (pOk, pErr, password) = InputValidator.ValidatePassword(model.Password);
    if (!pOk) return Results.BadRequest(new { error = pErr });

    var user = await repo.GetByUsernameAsync(username);
    if (user is null || !user.IsActive) return Results.Unauthorized();

    if (!PasswordHasher.Verify(password, user.PasswordHash)) return Results.Unauthorized();

    var (token, exp) = tokenService.CreateToken(user.Username, user.Role, TimeSpan.FromMinutes(30));
    return Results.Ok(new AuthResponse(token, exp, user.Username, user.Role));
});

// ---------- Protected JSON ----------
app.MapGet("/me", (System.Security.Claims.ClaimsPrincipal user) =>
{
    var username = user.Identity?.Name ?? "unknown";
    var role = user.Claims.FirstOrDefault(c => c.Type == System.Security.Claims.ClaimTypes.Role)?.Value ?? "unknown";
    return Results.Ok(new { username, role });
}).RequireAuthorization();

app.MapGet("/admin/dashboard", () => Results.Ok(new { message = "Welcome to Admin Dashboard." }))
   .RequireAuthorization("AdminOnly");

// ---------- User-generated content (XSS focus area) ----------
app.MapPost("/comments", (System.Security.Claims.ClaimsPrincipal user, CommentRequest model) =>
{
    var username = user.Identity?.Name ?? "unknown";
    var comment = model.Comment ?? "";

    if (comment.Length > 500) return Results.BadRequest(new { error = "Comment too long." });

    comments[username] = comment;
    return Results.Ok(new { saved = true });
}).RequireAuthorization();

// HTML page: ALWAYS encode output to prevent XSS
app.MapGet("/profile", (System.Security.Claims.ClaimsPrincipal user) =>
{
    var username = user.Identity?.Name ?? "unknown";
    var role = user.Claims.FirstOrDefault(c => c.Type == System.Security.Claims.ClaimTypes.Role)?.Value ?? "unknown";
    comments.TryGetValue(username, out var commentRaw);

    var enc = HtmlEncoder.Default;
    var usernameHtml = enc.Encode(username);
    var roleHtml = enc.Encode(role);
    var commentHtml = enc.Encode(commentRaw ?? "");

    var html = $@"
<!doctype html>
<html lang=""en"">
<head>
  <meta charset=""utf-8""/>
  <title>SafeVault Profile</title>
</head>
<body>
  <h1>Profile</h1>
  <p><b>User:</b> {usernameHtml}</p>
  <p><b>Role:</b> {roleHtml}</p>
  <h2>Latest Comment</h2>
  <div id=""comment"">{commentHtml}</div>
</body>
</html>";

    return Results.Content(html, "text/html; charset=utf-8");
}).RequireAuthorization();

app.Run();

public partial class Program { }
