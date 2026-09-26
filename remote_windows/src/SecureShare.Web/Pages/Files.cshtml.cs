using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Net.Http.Headers;

namespace SecureShare.Web.Pages;

public sealed class FilesModel(AccessStore access, FileStore files, FileTransferGate gate, SignInManager<AppUser> signIn, AuditStore audit) : PageModel
{
    public AccountAccess? Current { get; private set; }
    public List<StoredFile> Items { get; private set; } = [];
    public List<StoredFile> DeletingItems { get; private set; } = [];
    public long UsedBytes { get; private set; }
    public long QuotaBytes { get; private set; }
    public string? DeleteMessage { get; private set; }

    public async Task<IActionResult> OnGetAsync()
    {
        Current = await access.CurrentAsync(User);
        if (Current is null) return RedirectToPage("/Login");
        await LoadAsync();
        return Page();
    }

    public async Task<IActionResult> OnPostDeleteAsync(string id, string? confirmation)
    {
        Current = await access.CurrentAsync(User);
        if (Current is null || !Current.IsAdmin && Current.State != "owner") return Forbid();
        if (confirmation != "delete") DeleteMessage = "복원 불가와 연결 공유 무효화를 확인하세요.";
        else
        {
            var actorId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (actorId is null) return Forbid();
            var result = await files.DeleteAsync(id, actorId);
            if (result == FileDeleteResult.Forbidden)
            {
                await audit.RecordAsync(User, "file.delete", null, "denied");
                return Forbid();
            }
            DeleteMessage = result switch
            {
                FileDeleteResult.Deleted => "파일과 연결 공유를 영구 삭제했습니다.",
                FileDeleteResult.RetryNeeded => "삭제 처리 중입니다. 완료되지 않아 재시도가 필요합니다.",
                _ => "삭제할 수 있는 파일을 찾을 수 없습니다."
            };
        }
        await LoadAsync();
        return Page();
    }

    private async Task LoadAsync()
    {
        Items = await files.ListAsync();
        if (Current?.IsAdmin == true || Current?.State == "owner")
            DeletingItems = await files.ListDeletingAsync();
        (UsedBytes, QuotaBytes) = await files.UsageAsync();
    }

    public async Task<IActionResult> OnGetDownloadAsync(string id)
    {
        await gate.Transfer.WaitAsync(HttpContext.RequestAborted);
        byte[]? plain = null;
        try
        {
            var current = await access.CurrentAsync(User);
            if (current is null || !current.IsAdmin && current.State is not ("viewer" or "owner")) return Forbid();
            var file = await files.FindAvailableAsync(id);
            if (file is null) return NotFound();
            plain = await files.DecryptAsync(file, HttpContext.RequestAborted);
            if (plain is null)
            {
                await audit.RecordAsync(User, "file.integrity_or_unavailable", file.Id, "failure");
                return NotFound();
            }
            var actorId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (actorId is null) return Forbid();
            await files.RecordDownloadAsync(actorId, file.Id, "file.download.started", "success", HttpContext.RequestAborted);
            Response.ContentType = "application/octet-stream";
            Response.ContentLength = plain.Length;
            Response.Headers.CacheControl = "no-store";
            Response.Headers.XContentTypeOptions = "nosniff";
            Response.Headers.ContentDisposition = new ContentDispositionHeaderValue("attachment")
            {
                FileName = "download",
                FileNameStar = file.OriginalName
            }.ToString();
            try { await Response.Body.WriteAsync(plain, HttpContext.RequestAborted); }
            catch (Exception exception) when (exception is IOException or OperationCanceledException)
            {
                await files.RecordDownloadAsync(actorId, file.Id, "file.download.interrupted", "failure", CancellationToken.None);
                throw;
            }
            await files.RecordDownloadAsync(actorId, file.Id, "file.download.sent", "success", CancellationToken.None);
            return new EmptyResult();
        }
        finally
        {
            if (plain is not null) CryptographicOperations.ZeroMemory(plain);
            gate.Transfer.Release();
        }
    }

    public async Task<IActionResult> OnPostLogoutAsync()
    {
        await signIn.SignOutAsync();
        return RedirectToPage("/Login");
    }
}
