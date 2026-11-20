using System.Text.Json;
using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using HANKAN.Web;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.RazorPages;

var directory = Path.Combine(Path.GetTempPath(), "hankan-check-" + Guid.NewGuid().ToString("N"));
var webRoot = Path.Combine(directory, "wwwroot");
AccessModeSettings Parse(string json) => AccessModeSettings.Parse(json, directory, webRoot, 55180);
void Require(bool condition, string name)
{
    if (!condition) throw new Exception(name);
}
void Reject(string json)
{
    try { Parse(json); }
    catch (Exception exception) when (exception is InvalidDataException or JsonException) { return; }
    throw new Exception("Invalid configuration accepted");
}
Require(AccessModeSettings.Load(directory, webRoot, 55180).Mode == "local", "Missing file must be local");
Require(Parse("""{"version":1,"mode":"local"}""").TrustedProxyIps.Length == 0, "Empty trust");
Require(Parse("""{"version":1,"mode":"direct","direct":{"address":"127.0.0.1","port":55443,"transport":"http","allowHttp":true}}""").Mode == "direct", "Explicit HTTP");
Require(Parse("""{"version":1,"mode":"tunnel","trustedProxyIps":["127.0.0.1"]}""").Tunnel?.TokenFile is null, "Quick selection");
foreach (var json in new[]
{
    """{}""", """{"version":2,"mode":"local"}""", """{"version":1,"mode":"other"}""",
    """{"version":1,"mode":"local","token":"secret"}""", """{"version":1,"mode":"local","mode":"direct"}""",
    """{"version":1,"mode":"local","trustedProxyIps":null}""",
    """{"version":1,"mode":"local","trustedProxyIps":["192.0.2.0/24"]}""",
    """{"version":1,"mode":"direct","direct":{"address":"localhost","port":55443,"transport":"http","allowHttp":true}}""",
    """{"version":1,"mode":"direct","direct":{"port":55443,"transport":"http","allowHttp":true}}""",
    """{"version":1,"mode":"direct","direct":{"address":"127.0.0.1","transport":"http","allowHttp":true}}""",
    """{"version":1,"mode":"direct","direct":{"address":"127.0.0.1","port":55180,"transport":"http","allowHttp":true}}""",
    """{"version":1,"mode":"direct","direct":{"address":"127.0.0.1","port":65536,"transport":"http","allowHttp":true}}""",
    """{"version":1,"mode":"direct","direct":{"address":"127.0.0.1","port":55443,"transport":"http"}}""",
    """{"version":1,"mode":"tunnel"}""",
    """{"version":1,"mode":"tunnel","trustedProxyIps":["127.0.0.1"],"tunnel":{"tokenFile":"../token","publicOrigin":"https://example.test"}}""",
    """{"version":1,"mode":"tunnel","trustedProxyIps":["127.0.0.1"],"tunnel":{"tokenFile":"access-secrets/token.dpapi","publicOrigin":"https://example.test/path"}}"""
}) Reject(json);
try { AccessSecrets.CheckPath(Path.Combine(webRoot, "certificate.pfx"), webRoot); throw new Exception("Static path accepted"); }
catch (InvalidDataException) { }
Console.WriteLine("PASS: access configuration defaults, strict schema, endpoints, trust, secret boundaries");
var trustSettings = Parse("""{"version":1,"mode":"tunnel","trustedProxyIps":["127.0.0.1"]}""");
var runtime = new AccessModeRuntime(trustSettings, 55180);
Require(!runtime.IsTrustedPeer(IPAddress.Loopback), "Local ignores all proxies");
runtime.EffectiveMode = "tunnel";
Require(runtime.IsTrustedPeer(IPAddress.Parse("::ffff:127.0.0.1")), "Mapped proxy normalization");
Require(!runtime.IsTrustedPeer(IPAddress.Parse("192.0.2.10")), "Unlisted proxy");
var request = new DefaultHttpContext().Request;
Require(!AccessModeRuntime.ValidForwarding(request), "Missing forwarding");
request.Headers["CF-Connecting-IP"] = "192.0.2.10";
request.Headers["X-Forwarded-Proto"] = "https";
Require(AccessModeRuntime.ValidForwarding(request), "Single pair");
foreach (var invalid in new[] { "192.0.2.10, 192.0.2.11", "invalid", "" })
{
    request.Headers["CF-Connecting-IP"] = invalid;
    Require(!AccessModeRuntime.ValidForwarding(request), "Invalid forwarding");
}
request.Headers["CF-Connecting-IP"] = "192.0.2.10";
request.Headers["X-Forwarded-Proto"] = "https,http";
Require(!AccessModeRuntime.ValidForwarding(request), "Multiple proto");
foreach (var page in new[] { "/Login", "/Register", "/Shares" })
{
    var http = new DefaultHttpContext();
    http.Request.Method = "POST";
    http.Request.QueryString = new QueryString("?handler=cReAtE");
    var descriptor = new PageActionDescriptor { ViewEnginePath = page };
    Require(await PasswordTransportFilter.RequiresHttpsAsync(http, descriptor), "HTTP password POST");
    http.Items["HANKAN.PasswordTransport"] = true;
    Require(!await PasswordTransportFilter.RequiresHttpsAsync(http, descriptor), "HTTPS continues existing validation");
}
Console.WriteLine("PASS: peer trust, one-hop header validation, HTTP password rejection, HTTPS continuation");
foreach (var state in new[] { SetupState.Unconfigured, SetupState.RecoveryRequired })
{
    using var mode = new AccessModeRuntime(trustSettings, 55180);
    mode.Apply(state, directory, webRoot, false);
    Require(mode.EffectiveMode == "local" && mode.RestartRequired && !mode.Applied, "Bootstrap never opens tunnel");
}
using (var mode = new AccessModeRuntime(trustSettings, 55180))
{
    mode.Apply(SetupState.Ready, directory, webRoot, false);
    Require(mode.EffectiveMode == "tunnel" && mode.Applied, "Ready applies requested mode");
    mode.FallBack("test failure");
    Require(mode.EffectiveMode == "local" && !mode.Applied && mode.Requested.Mode == "tunnel", "Failure preserves request");
}
using (var mode = new AccessModeRuntime(trustSettings, 55180))
{
    mode.Apply(SetupState.Ready, directory, webRoot, true);
    Require(mode.EffectiveMode == "local" && !mode.Applied, "Forced local never opens tunnel");
}
Console.WriteLine("PASS: startup setup invariant, mode application, local fallback");
Require(HankanChild.AllowedTunnelLine("debug token=sample-secret", "sample-secret", false) == "", "Token/debug dropped");
Require(HankanChild.AllowedTunnelLine("Registered tunnel connection protocol=http2 token=sample-secret", "sample-secret", false)
    == "tunnel connection ready", "Connection output whitelist");
Require(HankanChild.AllowedTunnelLine("URL https://sample.trycloudflare.com", "", true)
    == "https://sample.trycloudflare.com", "Quick URL extraction");
Require(HankanChild.AllowedTunnelLine("URL https://sample.trycloudflare.com", "", false) == "", "Fixed never adopts Quick URL");
Require(HankanChild.AllowedTunnelLine("URL https://sample.trycloudflare.com", "sample", true) == "", "Redact before extraction");
Console.WriteLine("PASS: tunnel output whitelist, token removal, Quick/fixed separation");

int FreePort()
{
    using var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    return ((IPEndPoint)listener.LocalEndpoint).Port;
}

// Exercise Program.cs itself: parser failures must still leave a live local host.
Directory.CreateDirectory(directory);
try
{
    foreach (var invalid in new[]
    {
        """{"version":1,"mode":"direct","direct":{"address":"127.0.0.1","port":PORT,"transport":"http"}}""",
        """{"version":2,"mode":"direct","direct":{"address":"127.0.0.1","port":PORT,"transport":"http","allowHttp":true}}""",
        """{"version":1,"mode":"direct","direct":{"port":PORT,"transport":"http","allowHttp":true}}""",
        """{"version":1,"mode":"direct","direct":{"address":"127.0.0.1","transport":"http","allowHttp":true}}""",
        """{"version":1,"mode":"tunnel","trustedProxyIps":[]}""",
        """{"version":1,"mode":"tunnel","trustedProxyIps":["127.0.0.1"],"tunnel":{"tokenFile":"../r1-regression-secret","publicOrigin":"https://example.test"}}""",
        """{"version":1,"mode":"local","unexpected":"r1-regression-secret"}""",
        """{"version":1,"mode":"local","mode":"direct"}""",
        """{"version":1,"mode":"local","trustedProxyIps":null}""",
        """{"version":1,"mode":"local","trustedProxyIps":["invalid"]}""",
        """{"version":1,"mode":"tunnel","trustedProxyIps":["127.0.0.1"],"tunnel":{"tokenFile":"access-secrets/\u0000r1-regression-secret","publicOrigin":"https://example.test"}}"""
    })
    {
        var localPort = FreePort();
        var externalPort = FreePort();
        while (externalPort == localPort) externalPort = FreePort();
        var data = Path.Combine(directory, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(data);
        if (OperatingSystem.IsWindows())
        {
            var acl = new System.Security.AccessControl.DirectorySecurity();
            acl.SetAccessRuleProtection(true, false);
            acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                System.Security.Principal.WindowsIdentity.GetCurrent().User!,
                System.Security.AccessControl.FileSystemRights.FullControl,
                System.Security.AccessControl.InheritanceFlags.ContainerInherit |
                    System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                System.Security.AccessControl.PropagationFlags.None,
                System.Security.AccessControl.AccessControlType.Allow));
            System.IO.FileSystemAclExtensions.SetAccessControl(new DirectoryInfo(data), acl);
        }
        await File.WriteAllTextAsync(Path.Combine(data, "access-mode.json"),
            invalid.Replace("PORT", externalPort.ToString()));
        var assembly = typeof(AccessModeRuntime).Assembly.Location;
        var start = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = Path.GetDirectoryName(assembly)!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        start.ArgumentList.Add(assembly);
        start.ArgumentList.Add("--Logging:LogLevel:Microsoft.Hosting.Lifetime=Information");
        var startupId = Guid.NewGuid().ToString("N");
        start.Environment["HANKAN_DATA_DIR"] = data;
        start.Environment["HANKAN_PORT"] = localPort.ToString();
        start.Environment["HANKAN_STARTUP_ID"] = startupId;
        start.Environment.Remove("HANKAN_FORCE_LOCAL");
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var output = new List<string>();
        using var process = new Process { StartInfo = start };
        process.OutputDataReceived += (_, line) =>
        {
            if (line.Data is null) return;
            output.Add(line.Data);
            if (line.Data.Contains("Application started.")) started.TrySetResult();
        };
        Require(process.Start(), "Start real app");
        process.BeginOutputReadLine();
        var errors = process.StandardError.ReadToEndAsync();
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var exited = process.WaitForExitAsync(timeout.Token);
            Require(await Task.WhenAny(started.Task, exited) == started.Task, "Invalid settings terminated app");
            await started.Task.WaitAsync(timeout.Token);
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            client.DefaultRequestHeaders.Add("X-Hankan-Startup-Id", startupId);
            var response = await client.GetAsync($"http://127.0.0.1:{localPort}/_local/startup");
            var body = await response.Content.ReadAsStringAsync();
            using var status = JsonDocument.Parse(body);
            Require(response.StatusCode == HttpStatusCode.ServiceUnavailable, "Unconfigured app stays up");
            Require(status.RootElement.GetProperty("effectiveMode").GetString() == "local" &&
                !status.RootElement.GetProperty("applied").GetBoolean() &&
                status.RootElement.GetProperty("failure").GetString() == "접속 모드 설정 파일을 확인할 수 없음",
                "Configuration failure must be local, unapplied and secret-free");
            Require(!body.Contains("r1-regression-secret"), "No secret in startup response");
            // Binding the requested external port proves the app did not keep that listener.
            using var external = new TcpListener(IPAddress.Any, externalPort);
            external.Start();
            Require(!process.HasExited, "App remains running after startup request");
        }
        finally
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            process.WaitForExit(); // Drain the asynchronous stdout event callbacks.
        }
        var error = await errors;
        Require(!string.Join('\n', output).Contains("r1-regression-secret") &&
            !error.Contains("r1-regression-secret"), "No secret in host diagnostics");
        var listeners = output.Where(line => line.Contains("Now listening on:")).ToArray();
        Require(listeners.Length == 1 && listeners[0].Contains($"http://127.0.0.1:{localPort}"),
            "Real host has only the local listener");
    }
    Console.WriteLine("PASS: real app survives 11 invalid configurations, local listener only, applied=false, secret-free");
}
finally { Directory.Delete(directory, recursive: true); }

using var rsa = RSA.Create(2048);
var certificateRequest = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256,
    RSASignaturePadding.Pkcs1);
using var generated = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),
    DateTimeOffset.UtcNow.AddDays(1));
var pfx = generated.Export(X509ContentType.Pkcs12);
using var certificate = X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.UserKeySet);
CryptographicOperations.ZeroMemory(pfx);
foreach (var useTls in new[] { true, false })
{
    var port = FreePort();
    using var mode = new AccessModeRuntime(new AccessModeSettings
    {
        Version = 1, Mode = "direct",
        Direct = new DirectAccessSettings { Address = "127.0.0.1", Port = port, Transport = "https" }
    }, FreePort()) { EffectiveMode = "direct" };
    var builder = WebApplication.CreateBuilder();
    builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, port, endpoint =>
    {
        if (useTls) endpoint.UseHttps(certificate);
    }));
    await using var host = builder.Build();
    await host.StartAsync();
    try
    {
        Require(!mode.Applied, "TLS is not applied before a handshake");
        try { await mode.CheckDirectTlsAsync(); }
        catch (Exception exception) when (!useTls && exception is AuthenticationException or IOException)
        {
            mode.FallBack("직접 수신 또는 TLS 확인 실패");
        }
        Require(useTls ? mode.Applied : mode.EffectiveMode == "local" && !mode.Applied,
            "TLS handshake controls application success");
    }
    finally { await host.StopAsync(); }
}
Console.WriteLine("PASS: direct TLS success requires a real Kestrel handshake; handshake failure stays unapplied");
