using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;
using SafeVault.Api.Models;
using SafeVault.Data.Users;

namespace SafeVault.Tests;

public class TestSecurityFixes
{
    private WebApplicationFactory<Program> _factory = null!;
    private HttpClient _client = null!;

    [SetUp]
    public void Setup()
    {
        _factory = new WebApplicationFactory<Program>();
        _client = _factory.CreateClient();
    }

    [TearDown]
    public void TearDown()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    private async Task<string> RegisterAndLogin(string username, string email, string role)
    {
        var reg = new RegisterRequest(username, email, "Password#123", role);
        var regRes = await _client.PostAsJsonAsync("/auth/register", reg);
        Assert.That(regRes.StatusCode, Is.EqualTo(HttpStatusCode.Created));

        var login = new LoginRequest(username, "Password#123");
        var loginRes = await _client.PostAsJsonAsync("/auth/login", login);
        Assert.That(loginRes.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var auth = await loginRes.Content.ReadFromJsonAsync<AuthResponse>();
        Assert.That(auth, Is.Not.Null);
        return auth!.Token;
    }

    [Test]
    public async Task Security_headers_are_present()
    {
        var token = await RegisterAndLogin("hdruser1", "hdr1@example.com", "User");
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var res = await _client.GetAsync("/me");
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        Assert.That(res.Headers.Contains("Content-Security-Policy"), Is.True);
        Assert.That(res.Headers.Contains("X-Content-Type-Options"), Is.True);
        Assert.That(res.Headers.Contains("X-Frame-Options"), Is.True);
        Assert.That(res.Headers.Contains("Referrer-Policy"), Is.True);
    }

    [Test]
    public async Task Xss_payload_is_escaped_in_profile_html()
    {
        var token = await RegisterAndLogin("xssuser1", "xss1@example.com", "User");
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var payload = new CommentRequest("<script>alert(1)</script><img src=x onerror=alert(2)>");
        var post = await _client.PostAsJsonAsync("/comments", payload);
        Assert.That(post.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var profile = await _client.GetAsync("/profile");
        Assert.That(profile.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var html = await profile.Content.ReadAsStringAsync();

        Assert.That(html, Does.Contain("&lt;script&gt;"));
        Assert.That(html, Does.Not.Contain("<script>"));
        Assert.That(html, Does.Not.Contain("onerror="));
    }

    [Test]
    public void Sql_injection_like_input_is_not_concatenated_into_command_text()
    {
        var injection = "admin' OR '1'='1";
        var cmd = typeof(MySqlUserRepository)
            .GetMethod("BuildLookupCommand", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!
            .Invoke(null, new object[] { injection });

        dynamic d = cmd!;
        Assert.That((string)d.CommandText, Does.Contain("@username"));
        Assert.That((string)d.CommandText, Does.Not.Contain(injection));
        Assert.That(d.Parameters.Count, Is.EqualTo(1));
        Assert.That((string)d.Parameters[0].ParameterName, Is.EqualTo("@username"));
        Assert.That((string)d.Parameters[0].Value, Is.EqualTo(injection));
    }

    [Test]
    public async Task Rbac_still_blocks_non_admins()
    {
        var token = await RegisterAndLogin("rbacuser1", "rbac1@example.com", "User");
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var res = await _client.GetAsync("/admin/dashboard");
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }
}
