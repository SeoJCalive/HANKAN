using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Net.Http.Headers;
using System.Globalization;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.RateLimiting;
using HANKAN.Web;

var builder = WebApplication.CreateBuilder(args);
var port = int.TryParse(Environment.GetEnvironmentVariable("HANKAN_PORT"), out var configuredPort) && configuredPort is > 1023 and < 65536
    ? configuredPort : 5180;
var accessMode = new AccessModeRuntime(AccessModeSettings.Local, port);
builder.Services.AddSingleton(accessMode);
builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 100_100_000);
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders =
        ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.ForwardedForHeaderName = "CF-Connecting-IP";
    options.ForwardedProtoHeaderName = "X-Forwarded-Proto";
    options.ForwardLimit = 1;
    options.RequireHeaderSymmetry = true;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
    foreach (var ip in accessMode.Requested.TrustedProxyIps)
        options.KnownProxies.Add(AccessModeSettings.Normalize(IPAddress.Parse(ip)));
});
builder.Services.AddRazorPages(options =>
{
    options.Conventions.AuthorizePage("/Access", "Member");
    options.Conventions.AuthorizePage("/Files", "Viewer");
    options.Conventions.AuthorizePage("/Admin/Users", "Admin");
    options.Conventions.AuthorizePage("/Admin/Audit", "Admin");
    options.Conventions.AuthorizePage("/Admin/Configuration", "Admin");
    options.Conventions.AuthorizePage("/Shares", "Owner");
});
builder.Services.Configure<Microsoft.AspNetCore.Mvc.MvcOptions>(options =>
    options.Filters.Add<PasswordTransportFilter>());
builder.Services.AddScoped<AccessStore>();
builder.Services.AddScoped<FileStore>();
builder.Services.AddScoped<FolderStore>();
builder.Services.AddScoped<SelectionResolver>();
builder.Services.AddScoped<BulkMoveStore>();
builder.Services.AddScoped<BulkDeleteStore>();
builder.Services.AddScoped<ShareStore>();
builder.Services.AddScoped<AuditStore>();
builder.Services.AddSingleton<IAuditKeyProtector, WindowsAuditKeyProtector>();
builder.Services.AddSingleton<FileTransferGate>();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<PowCaptcha>();
builder.Services.AddScoped<IAuthorizationHandler, AccessHandler>();
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Member", policy => policy.Requirements.Add(new AccessRequirement("member")));
    options.AddPolicy("Viewer", policy => policy.Requirements.Add(new AccessRequirement("viewer")));
    options.AddPolicy("Owner", policy => policy.Requirements.Add(new AccessRequirement("owner")));
    options.AddPolicy("Admin", policy => policy.Requirements.Add(new AccessRequirement("admin")));
});
var dataDirectory = Path.GetFullPath(Environment.GetEnvironmentVariable("HANKAN_DATA_DIR")
    ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HANKAN"));
builder.Services.AddDbContext<AppDbContext>(options => options.UseSqlite(new SqliteConnectionStringBuilder
{
    DataSource = Path.Combine(dataDirectory, "hankan.db")
}.ToString()));
builder.Services.AddIdentity<AppUser, IdentityRole>(options =>
    {
        options.Password.RequiredLength = 12;
        options.Password.RequireDigit = false;
        options.Password.RequireLowercase = false;
        options.Password.RequireUppercase = false;
        options.Password.RequireNonAlphanumeric = false;
        options.User.RequireUniqueEmail = true;
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
    })
    .AddEntityFrameworkStores<AppDbContext>();
// Existing Identity PBKDF2 hashes only; new passwords use Argon2id.
builder.Services.Configure<PasswordHasherOptions>(options => options.IterationCount = 210_000);
builder.Services.AddScoped<IPasswordHasher<AppUser>, Argon2idPasswordHasher>();
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Login";
    options.AccessDeniedPath = "/Access";
    options.Cookie.Name = "HANKAN.Session";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
    options.SlidingExpiration = false;
    options.Events.OnRedirectToAccessDenied = context =>
    {
        if (context.Request.Method == "POST") context.Response.StatusCode = StatusCodes.Status403Forbidden;
        else context.Response.Redirect(context.RedirectUri);
        return Task.CompletedTask;
    };
});
builder.Services.AddSingleton<SetupStore>();
builder.Services.AddRateLimiter(options =>
{
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
    {
        if (!HttpMethods.IsPost(context.Request.Method))
            return RateLimitPartition.GetNoLimiter("other");

        var path = context.Request.Path;
        var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var userId = context.User.Identity?.IsAuthenticated == true
            ? context.User.FindFirstValue(ClaimTypes.NameIdentifier)
            : null;
        (string Key, int Limit, int Minutes)? policy =
            path.Equals("/Login", StringComparison.OrdinalIgnoreCase)
                ? ($"login:{ip}", 20, 1)
            : path.Equals("/Register", StringComparison.OrdinalIgnoreCase)
                ? ($"register:{ip}", 5, 10)
            : path.Equals("/Access", StringComparison.OrdinalIgnoreCase)
                ? ($"access:{ip}", 10, 1)
            : path.StartsWithSegments("/Share", StringComparison.OrdinalIgnoreCase)
                ? ($"share:{ip}", 30, 1)
            : path.StartsWithSegments("/Shares", StringComparison.OrdinalIgnoreCase)
                && userId is not null
                ? ($"shares:{userId}", 30, 1)
            : null;

        return policy is { } selected
            ? RateLimitPartition.GetFixedWindowLimiter(selected.Key, _ =>
                new FixedWindowRateLimiterOptions
                {
                    PermitLimit = selected.Limit,
                    Window = TimeSpan.FromMinutes(selected.Minutes),
                    QueueLimit = 0
                })
            : RateLimitPartition.GetNoLimiter("other");
    });
    options.OnRejected = async (context, cancellationToken) =>
    {
        await context.HttpContext.RequestServices.GetRequiredService<AuditStore>()
            .RecordAsync(context.HttpContext.User, "defense.rate_limited", null, "denied");
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        context.HttpContext.Response.ContentType = "text/plain; charset=utf-8";
        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
            context.HttpContext.Response.Headers.RetryAfter =
                Math.Max(1, Math.Ceiling(retryAfter.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
        await context.HttpContext.Response.WriteAsync(
            "요청이 많아 잠시 제한되었습니다. 잠시 후 이전 화면으로 돌아가 다시 시도하세요.", cancellationToken);
    };
});

if (string.Equals(builder.Configuration["ForwardedHeaders_Enabled"], "true",
    StringComparison.OrdinalIgnoreCase))
{
    throw new InvalidOperationException(
        "HANKAN_FORWARDING_AUTO_ENABLE_FORBIDDEN: ForwardedHeaders_Enabled=true.");
}
builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
{
    ["ForwardedHeaders_Enabled"] = "false"
});

var app = builder.Build();
var setup = app.Services.GetRequiredService<SetupStore>();
var startupId = Environment.GetEnvironmentVariable("HANKAN_STARTUP_ID");
if (setup.State == SetupState.Ready)
{
    using var scope = app.Services.CreateScope();
    try
    {
        await scope.ServiceProvider.GetRequiredService<AppDbContext>().PruneAuditAsync();
        await scope.ServiceProvider.GetRequiredService<FileStore>().RecoverAsync();
    }
    catch (AuditIntegrityException exception)
    {
        app.Logger.LogError(exception, "Audit integrity failed at startup; retention and file recovery are suspended. Read-only administrator verification remains available.");
    }
}
if (setup.State == SetupState.Unconfigured)
{
    if (string.IsNullOrEmpty(startupId))
        Console.WriteLine($"한칸(HANKAN) 최초 설정 코드: {setup.SetupCode}");
    else
        Console.WriteLine("한칸(HANKAN) 수동 콘솔에서 최초 설정이 필요합니다.");
}
else if (setup.State == SetupState.RecoveryRequired)
    Console.Error.WriteLine("한칸(HANKAN) 데이터 또는 저장소를 확인할 수 없습니다. 복구가 필요합니다.");
app.Use(async (context, next) =>
{
    context.Response.Headers.XContentTypeOptions = "nosniff";
    context.Response.Headers.XFrameOptions = "DENY";
    if (!context.Request.Path.Equals("/_local/startup", StringComparison.OrdinalIgnoreCase))
    {
        await next();
        return;
    }
    context.Response.Headers.CacheControl = "no-store";
    if (!HttpMethods.IsGet(context.Request.Method) ||
        !accessMode.IsLocalControl(context) ||
        string.IsNullOrEmpty(startupId) ||
        context.Request.Headers["X-Hankan-Startup-Id"].Count != 1 ||
        context.Request.Headers["X-Hankan-Startup-Id"][0] != startupId)
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return;
    }
    var ready = app.Lifetime.ApplicationStarted.IsCancellationRequested && setup.State == SetupState.Ready;
    context.Response.StatusCode = ready ? 200 : 503;
    await context.Response.WriteAsJsonAsync(new { setupReady = ready, processId = Environment.ProcessId });
});
app.Use(async (context, next) =>
{
    if (string.Equals(context.Request.Path.Value?.TrimEnd('/'), "/Login", StringComparison.OrdinalIgnoreCase) ||
        context.Request.Path.StartsWithSegments("/Share", StringComparison.OrdinalIgnoreCase))
    {
        context.Response.Headers.ContentSecurityPolicy = "default-src 'self'; script-src 'self'; worker-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
        context.Response.Headers.CacheControl = "no-store";
    }
    if (context.Request.Path.StartsWithSegments("/Share") ||
        context.Request.Path.StartsWithSegments("/Shares") ||
        context.Request.Path.StartsWithSegments("/Public"))
    {
        context.Response.Headers["Referrer-Policy"] = "no-referrer";
        context.Response.Headers.CacheControl = "no-store";
    }
    await next();
});
app.Use(async (context, next) =>
{
    var localControl = accessMode.IsLocalControl(context);
    context.Items["HANKAN.LocalControl"] = localControl;
    if ((context.Request.Path.StartsWithSegments("/Setup", StringComparison.OrdinalIgnoreCase) ||
         context.Request.Path.StartsWithSegments("/Recovery", StringComparison.OrdinalIgnoreCase)) && !localControl)
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        await context.Response.WriteAsync("설정과 복구는 서버 PC의 로컬 주소에서 진행하세요.");
        return;
    }
    context.Items["HANKAN.DirectTls"] = context.Request.IsHttps;
    if (context.Connection.RemoteIpAddress is { } peer)
        context.Connection.RemoteIpAddress = AccessModeSettings.Normalize(peer);
    var trusted = accessMode.IsTrustedPeer(context.Connection.RemoteIpAddress);
    // Control pages retain their original local connection; they never consume forwarding.
    var controlPage = context.Request.Path.StartsWithSegments("/Setup", StringComparison.OrdinalIgnoreCase) ||
        context.Request.Path.StartsWithSegments("/Recovery", StringComparison.OrdinalIgnoreCase);
    if (trusted && !controlPage && !AccessModeRuntime.ValidForwarding(context.Request))
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        await context.Response.WriteAsync("전달 헤더가 올바르지 않습니다. HTTP는 평문 전송이며 비밀번호 기능에는 HTTPS가 필요합니다.");
        return;
    }
    context.Items["HANKAN.Forward"] = trusted && !controlPage;
    await next();
});
app.UseWhen(context => context.Items["HANKAN.Forward"] is true, branch => branch.UseForwardedHeaders());
app.Use(async (context, next) =>
{
    if (context.Connection.RemoteIpAddress is { } ip)
        context.Connection.RemoteIpAddress = AccessModeSettings.Normalize(ip);
    context.Items["HANKAN.PasswordTransport"] = context.Items["HANKAN.DirectTls"] is true ||
        accessMode.EffectiveMode == "tunnel" && context.Items["HANKAN.Forward"] is true && context.Request.IsHttps;
    await next();
});
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseRateLimiter();
app.UseAuthorization();
app.MapPost("/FileUpload", async (HttpContext context, IAntiforgery antiforgery, AccessStore access,
    FileStore files, FileTransferGate gate, AuditStore audit) =>
{
    if (context.Request.ContentLength > 100_100_000)
    {
        await audit.RecordAsync(context.User, "file.upload", null, "failure");
        return Results.Text("요청 크기 제한을 넘었습니다.", statusCode: 413);
    }
    try { await antiforgery.ValidateRequestAsync(context); }
    catch (AntiforgeryValidationException)
    {
        await audit.RecordAsync(context.User, "defense.csrf", null, "denied");
        return Results.Text("요청 확인에 실패했습니다.", statusCode: 400);
    }
    if (!MediaTypeHeaderValue.TryParse(context.Request.ContentType, out var mediaType) ||
        !mediaType.MediaType.Equals("multipart/form-data", StringComparison.OrdinalIgnoreCase))
    {
        await audit.RecordAsync(context.User, "file.upload", null, "failure");
        return Results.Text("파일 요청 형식을 확인하세요.", statusCode: 400);
    }
    var boundary = HeaderUtilities.RemoveQuotes(mediaType.Boundary).Value;
    if (string.IsNullOrEmpty(boundary) || boundary.Length > 70)
    {
        await audit.RecordAsync(context.User, "file.upload", null, "failure");
        return Results.Text("파일 요청 형식을 확인하세요.", statusCode: 400);
    }
    await gate.Transfer.WaitAsync(context.RequestAborted);
    try
    {
        var current = await access.CurrentAsync(context.User);
        if (current is null || !current.IsAdmin && current.State != "owner") return Results.StatusCode(403);
        var actorId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (actorId is null) return Results.StatusCode(403);
        var reader = new MultipartReader(boundary, context.Request.Body) { BodyLengthLimit = FileStore.MaxFileBytes };
        var section = await reader.ReadNextSectionAsync(context.RequestAborted);
        if (section is null || !ContentDispositionHeaderValue.TryParse(section.ContentDisposition, out var disposition) ||
            HeaderUtilities.RemoveQuotes(disposition.Name).Value != "file" ||
            !disposition.DispositionType.Equals("form-data", StringComparison.OrdinalIgnoreCase))
        {
            await audit.RecordAsync(context.User, "file.upload", null, "failure");
            return Results.Text("파일 하나를 선택하세요.", statusCode: 400);
        }
        var name = HeaderUtilities.RemoveQuotes(disposition.FileNameStar.HasValue ? disposition.FileNameStar : disposition.FileName).Value;
        if (string.IsNullOrEmpty(name))
        {
            await audit.RecordAsync(context.User, "file.upload", null, "failure");
            return Results.Text("파일 이름을 확인하세요.", statusCode: 400);
        }
        var folderId = context.Request.Query.TryGetValue("folderId", out var selectedFolder) ? selectedFolder.ToString() : null;
        var error = await files.UploadAsync(section.Body, name, actorId, current.Email, folderId, context.RequestAborted);
        if (error is not null) await audit.RecordAsync(context.User, "file.upload", null, "failure");
        return error is null ? Results.Ok() : Results.Text(error, statusCode: 400);
    }
    catch (InvalidDataException)
    {
        await audit.RecordAsync(context.User, "file.upload", null, "failure");
        return Results.Text("파일당 최대 99,999,999바이트(약 95.4 MB)까지 업로드할 수 있습니다.", statusCode: 413);
    }
    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or CryptographicException or DbUpdateException)
    {
        await audit.RecordAsync(context.User, "file.upload", null, "failure");
        return Results.Text("파일을 저장할 수 없습니다. 저장소 상태를 확인하세요.", statusCode: 500);
    }
    finally { gate.Transfer.Release(); }
}).RequireAuthorization("Owner");
app.MapRazorPages();
app.Run($"http://127.0.0.1:{port}");
