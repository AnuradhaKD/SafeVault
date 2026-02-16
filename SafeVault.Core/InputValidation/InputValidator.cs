using System.Net.Mail;
using System.Text;
using System.Text.RegularExpressions;

namespace SafeVault.Core.InputValidation;

public static class InputValidator
{
    private static readonly Regex UsernameRegex = new(@"^[A-Za-z0-9_.-]{3,30}$", RegexOptions.Compiled);
    private static readonly Regex RoleRegex = new(@"^(Admin|User)$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static (bool Ok, string? Error, string Clean) ValidateUsername(string? username)
    {
        var clean = Normalize(username);

        if (string.IsNullOrWhiteSpace(clean))
            return (false, "Username is required.", string.Empty);

        if (clean.Length is < 3 or > 30)
            return (false, "Username must be 3–30 characters.", string.Empty);

        if (ContainsHtmlLikeChars(clean))
            return (false, "Username contains invalid characters.", string.Empty);

        if (!UsernameRegex.IsMatch(clean))
            return (false, "Username contains invalid characters.", string.Empty);

        return (true, null, clean);
    }

    public static (bool Ok, string? Error, string Clean) ValidateEmail(string? email)
    {
        var clean = Normalize(email);

        if (string.IsNullOrWhiteSpace(clean))
            return (false, "Email is required.", string.Empty);

        if (clean.Length > 100)
            return (false, "Email is too long.", string.Empty);

        if (ContainsHtmlLikeChars(clean))
            return (false, "Email contains invalid characters.", string.Empty);

        try
        {
            var addr = new MailAddress(clean);
            if (!string.Equals(addr.Address, clean, StringComparison.OrdinalIgnoreCase))
                return (false, "Email format is invalid.", string.Empty);
        }
        catch
        {
            return (false, "Email format is invalid.", string.Empty);
        }

        return (true, null, clean);
    }

    public static (bool Ok, string? Error, string Clean) ValidatePassword(string? password)
    {
        var clean = Normalize(password);

        if (string.IsNullOrWhiteSpace(clean))
            return (false, "Password is required.", string.Empty);

        if (clean.Length is < 8 or > 128)
            return (false, "Password must be 8–128 characters.", string.Empty);

        if (clean.Contains('<') || clean.Contains('>'))
            return (false, "Password contains invalid characters.", string.Empty);

        return (true, null, clean);
    }

    public static (bool Ok, string? Error, string Clean) ValidateRole(string? role)
    {
        var clean = Normalize(role);

        if (string.IsNullOrWhiteSpace(clean))
            return (false, "Role is required.", string.Empty);

        if (!RoleRegex.IsMatch(clean))
            return (false, "Role must be Admin or User.", string.Empty);

        clean = char.ToUpperInvariant(clean[0]) + clean[1..].ToLowerInvariant();
        return (true, null, clean);
    }

    private static string Normalize(string? s)
    {
        if (s is null) return string.Empty;

        var trimmed = s.Trim();
        var sb = new StringBuilder(trimmed.Length);

        foreach (var ch in trimmed)
        {
            if (!char.IsControl(ch))
                sb.Append(ch);
        }

        return sb.ToString();
    }

    private static bool ContainsHtmlLikeChars(string s)
        => s.Contains('<') || s.Contains('>') || s.Contains('"') || s.Contains('\'');
}
