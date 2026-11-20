using System.Text.Json;
using HANKAN.Web;
using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Routing;

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
    var action = new ActionContext(http, new RouteData(), new PageActionDescriptor { ViewEnginePath = page });
    var context = new AuthorizationFilterContext(action, []);
    await new PasswordTransportFilter().OnAuthorizationAsync(context);
    Require(context.Result is ContentResult { StatusCode: 403 }, "HTTP password POST");
    http.Items["HANKAN.PasswordTransport"] = true;
    context.Result = null;
    await new PasswordTransportFilter().OnAuthorizationAsync(context);
    Require(context.Result is null, "HTTPS continues existing validation");
}
Console.WriteLine("PASS: peer trust, one-hop header validation, HTTP password rejection, HTTPS continuation");
