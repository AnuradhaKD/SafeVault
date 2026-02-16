using System.Collections.Concurrent;

namespace SafeVault.Data.Users;

public sealed class InMemoryUserRepository : IUserRepository
{
    private readonly ConcurrentDictionary<string, UserRecord> _byUsername = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _emailToUsername = new(StringComparer.OrdinalIgnoreCase);
    private int _id = 0;

    public Task<UserRecord?> GetByUsernameAsync(string username, CancellationToken ct = default)
    {
        _byUsername.TryGetValue(username, out var user);
        return Task.FromResult(user);
    }

    public Task<UserRecord?> GetByEmailAsync(string email, CancellationToken ct = default)
    {
        if (_emailToUsername.TryGetValue(email, out var u) && _byUsername.TryGetValue(u, out var user))
            return Task.FromResult<UserRecord?>(user);

        return Task.FromResult<UserRecord?>(null);
    }

    public Task<int> CreateUserAsync(string username, string email, string passwordHash, string role, CancellationToken ct = default)
    {
        var id = Interlocked.Increment(ref _id);
        var record = new UserRecord(id, username, email, passwordHash, role, IsActive: true);

        if (!_byUsername.TryAdd(username, record))
            throw new InvalidOperationException("Username already exists.");

        if (!_emailToUsername.TryAdd(email, username))
        {
            _byUsername.TryRemove(username, out _);
            throw new InvalidOperationException("Email already exists.");
        }

        return Task.FromResult(id);
    }
}
