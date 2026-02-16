using MySqlConnector;

namespace SafeVault.Data.Users;

public sealed class MySqlUserRepository : IUserRepository
{
    private readonly string _connectionString;

    public MySqlUserRepository(string connectionString) => _connectionString = connectionString;

    public async Task<UserRecord?> GetByUsernameAsync(string username, CancellationToken ct = default)
    {
        const string sql = @"
SELECT UserID, Username, Email, PasswordHash, Role, IsActive
FROM Users
WHERE Username = @username
LIMIT 1;
";
        await using var conn = new MySqlConnection(_connectionString);
        await conn.OpenAsync(ct);

        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@username", username);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return null;

        return new UserRecord(
            reader.GetInt32("UserID"),
            reader.GetString("Username"),
            reader.GetString("Email"),
            reader.GetString("PasswordHash"),
            reader.GetString("Role"),
            reader.GetBoolean("IsActive")
        );
    }

    public async Task<UserRecord?> GetByEmailAsync(string email, CancellationToken ct = default)
    {
        const string sql = @"
SELECT UserID, Username, Email, PasswordHash, Role, IsActive
FROM Users
WHERE Email = @email
LIMIT 1;
";
        await using var conn = new MySqlConnection(_connectionString);
        await conn.OpenAsync(ct);

        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@email", email);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return null;

        return new UserRecord(
            reader.GetInt32("UserID"),
            reader.GetString("Username"),
            reader.GetString("Email"),
            reader.GetString("PasswordHash"),
            reader.GetString("Role"),
            reader.GetBoolean("IsActive")
        );
    }

    public async Task<int> CreateUserAsync(string username, string email, string passwordHash, string role, CancellationToken ct = default)
    {
        const string sql = @"
INSERT INTO Users (Username, Email, PasswordHash, Role, IsActive)
VALUES (@username, @email, @hash, @role, 1);
SELECT LAST_INSERT_ID();
";
        await using var conn = new MySqlConnection(_connectionString);
        await conn.OpenAsync(ct);

        await using var cmd = new MySqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("@username", username);
        cmd.Parameters.AddWithValue("@email", email);
        cmd.Parameters.AddWithValue("@hash", passwordHash);
        cmd.Parameters.AddWithValue("@role", role);

        var result = await cmd.ExecuteScalarAsync(ct);
        return Convert.ToInt32(result);
    }

    internal static MySqlCommand BuildLookupCommand(string username)
    {
        const string sql = "SELECT UserID FROM Users WHERE Username = @username LIMIT 1;";
        var cmd = new MySqlCommand(sql);
        cmd.Parameters.AddWithValue("@username", username);
        return cmd;
    }

    internal static string MapSortColumn(string sort)
        => sort.ToLowerInvariant() switch
        {
            "username" => "Username",
            "email" => "Email",
            "created" => "CreatedUtc",
            _ => "Username"
        };
}
