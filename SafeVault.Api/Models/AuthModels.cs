namespace SafeVault.Api.Models;

public sealed record RegisterRequest(string Username, string Email, string Password, string Role);
public sealed record LoginRequest(string Username, string Password);
public sealed record AuthResponse(string Token, DateTime ExpiresUtc, string Username, string Role);
public sealed record CommentRequest(string Comment);
