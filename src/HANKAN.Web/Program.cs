using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.RateLimiting;
using HANKAN.Web;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 100_100_000);
builder.Services.AddRazorPages(options =>
{
    options.Conventions.AuthorizePage("/Access", "Member");
    options.Conventions.AuthorizePage("/Files", "Viewer");
    options.Conventions.AuthorizePage("/Admin/Users", "Admin");
    options.Conventions.AuthorizePage("/Admin/Audit", "Admin");
    options.Conventions.AuthorizePage("/Shares", "Owner");
});
builder.Services.AddScoped<AccessStore>();
builder.Services.AddScoped<FileStore>();
builder.Services.AddScoped<FolderStore>();
builder.Services.AddScoped<SelectionResolver>();
builder.Services.AddScoped<BulkMoveStore>();
builder.Services.AddScoped<BulkDeleteStore>();
builder.Services.AddScoped<ShareStore>();
builder.Services.AddScoped<AuditStore>();
builder.Services.AddSingleton<FileTransferGate>();
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
builder.Services.Configure<PasswordHasherOptions>(options => options.IterationCount = 210_000);
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
        context.Request.Method == "POST" && (context.Request.Path.Equals("/Login", StringComparison.OrdinalIgnoreCase) ||
            context.Request.Path.Equals("/Register", StringComparison.OrdinalIgnoreCase) ||
            context.Request.Path.Equals("/Access", StringComparison.OrdinalIgnoreCase))
            ? RateLimitPartition.GetFixedWindowLimiter($"{context.Request.Path}:{context.Connection.RemoteIpAddress}", _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            })
            : context.Request.Method == "POST" && context.Request.Path.StartsWithSegments("/Share")
                ? RateLimitPartition.GetFixedWindowLimiter($"share:{context.Connection.RemoteIpAddress}", _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 10,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0
                })
                : RateLimitPartition.GetNoLimiter("other"));
    options.OnRejected = async (context, _) =>
    {
        await context.HttpContext.RequestServices.GetRequiredService<AuditStore>()
            .RecordAsync(context.HttpContext.User, "defense.rate_limited", null, "denied");
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
    };
});

var app = builder.Build();
var setup = app.Services.GetRequiredService<SetupStore>();
if (setup.State == SetupState.Ready)
{
    using var scope = app.Services.CreateScope();
    await scope.ServiceProvider.GetRequiredService<AppDbContext>().PruneAuditAsync();
    await scope.ServiceProvider.GetRequiredService<FileStore>().RecoverAsync();
}
if (setup.State == SetupState.Unconfigured)
    Console.WriteLine($"한칸(HANKAN) 최초 설정 코드: {setup.SetupCode}");
else if (setup.State == SetupState.RecoveryRequired)
    Console.Error.WriteLine("한칸(HANKAN) 데이터 또는 저장소를 확인할 수 없습니다. 복구가 필요합니다.");
app.UseStaticFiles();
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/Share") ||
        context.Request.Path.StartsWithSegments("/Shares") ||
        context.Request.Path.StartsWithSegments("/Public"))
    {
        context.Response.Headers["Referrer-Policy"] = "no-referrer";
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.XContentTypeOptions = "nosniff";
    }
    await next();
});
app.UseRouting();
app.UseRateLimiter();
app.UseAuthentication();
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
        return Results.Text("파일당 100 MB 미만으로 업로드하세요.", statusCode: 413);
    }
    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or CryptographicException or DbUpdateException)
    {
        await audit.RecordAsync(context.User, "file.upload", null, "failure");
        return Results.Text("파일을 저장할 수 없습니다. 저장소 상태를 확인하세요.", statusCode: 500);
    }
    finally { gate.Transfer.Release(); }
}).RequireAuthorization("Owner");
app.MapRazorPages();
var port = int.TryParse(Environment.GetEnvironmentVariable("HANKAN_PORT"), out var configuredPort) && configuredPort is > 1023 and < 65536
    ? configuredPort : 5180;
app.Run($"http://127.0.0.1:{port}");
