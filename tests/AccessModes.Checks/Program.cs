using System.Text.Json;
using HANKAN.Web;

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
