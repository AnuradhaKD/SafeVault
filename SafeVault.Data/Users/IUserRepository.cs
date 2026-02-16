namespace SafeVault.Data.Users;

public interface IUserRepository
{
    Task<UserRecord?> GetByUsernameAsync(string username, CancellationToken ct = default);
    Task<UserRecord?> GetByEmailAsync(string email, CancellationToken ct = default);
    Task<int> CreateUserAsync(string username, string email, string passwordHash, string role, CancellationToken ct = default);
}
