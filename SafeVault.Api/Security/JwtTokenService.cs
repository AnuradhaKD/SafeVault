using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace SafeVault.Api.Security;

public sealed class JwtTokenService
{
    private readonly string _issuer;
    private readonly string _audience;
    private readonly byte[] _keyBytes;

    public JwtTokenService(IConfiguration config)
    {
        _issuer = config["Jwt:Issuer"] ?? "SafeVault";
        _audience = config["Jwt:Audience"] ?? "SafeVaultUsers";
        var key = config["Jwt:Key"] ?? throw new InvalidOperationException("Jwt:Key missing.");
        _keyBytes = Encoding.UTF8.GetBytes(key);
        if (_keyBytes.Length < 32)
            throw new InvalidOperationException("Jwt:Key must be at least 32 characters for HS256.");
    }

    public (string Token, DateTime ExpiresUtc) CreateToken(string username, string role, TimeSpan lifetime)
    {
        var now = DateTime.UtcNow;
        var expires = now.Add(lifetime);

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, username),
            new(ClaimTypes.Role, role)
        };

        var creds = new SigningCredentials(new SymmetricSecurityKey(_keyBytes), SecurityAlgorithms.HmacSha256);

        var jwt = new JwtSecurityToken(
            issuer: _issuer,
            audience: _audience,
            claims: claims,
            notBefore: now,
            expires: expires,
            signingCredentials: creds
        );

        return (new JwtSecurityTokenHandler().WriteToken(jwt), expires);
    }

    public TokenValidationParameters GetValidationParameters() => new()
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateIssuerSigningKey = true,
        ValidateLifetime = true,
        ValidIssuer = _issuer,
        ValidAudience = _audience,
        IssuerSigningKey = new SymmetricSecurityKey(_keyBytes),
        ClockSkew = TimeSpan.FromSeconds(30)
    };
}
