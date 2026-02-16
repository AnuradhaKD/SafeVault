namespace SafeVault.Data.Users;

public sealed record UserRecord(
    int UserId,
    string Username,
    string Email,
    string PasswordHash,
    string Role,
    bool IsActive
);
