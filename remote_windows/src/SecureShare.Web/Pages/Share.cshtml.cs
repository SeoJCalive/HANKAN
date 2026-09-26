using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Net.Http.Headers;

namespace SecureShare.Web.Pages;

public sealed class ShareModel(ShareStore shares, FileStore files, FileTransferGate gate, AuditStore audit) : PageModel
{
    [BindProperty] public string? Password { get; set; }
    public SharedFile? Item { get; private set; }
    public string? Error { get; private set; }

    public async Task<IActionResult> OnGetAsync(string token)
    {
        Item = await shares.FindActiveAsync(token);
        if (Item is null) Response.StatusCode = StatusCodes.Status404NotFound;
        return Page();
    }

    public async Task<IActionResult> OnPostDownloadAsync(string token)
    {
        await gate.Transfer.WaitAsync(HttpContext.RequestAborted);
        byte[]? plain = null;
        try
        {
            var result = await shares.CheckPasswordAsync(token, Password);
            if (result != "ok")
            {
                if (result == "unavailable")
                {
                    await audit.RecordAsync(User, "share.access", null, "denied");
                    Response.StatusCode = StatusCodes.Status404NotFound;
                    return Page();
                }
                Error = result == "limited" ? "시도 제한에 걸렸습니다. 15분 뒤 다시 시도하세요." : "비밀번호가 올바르지 않습니다.";
                Item = await shares.FindActiveAsync(token);
                if (Item is null) Response.StatusCode = StatusCodes.Status404NotFound;
                return Page();
            }
            Item = await shares.FindActiveAsync(token);
            if (Item is null)
            {
                Response.StatusCode = StatusCodes.Status404NotFound;
                return Page();
            }
            var file = await files.FindAvailableAsync(Item.Id);
            if (file is null)
            {
                Response.StatusCode = StatusCodes.Status404NotFound;
                return Page();
            }
            plain = await files.DecryptAsync(file, HttpContext.RequestAborted);
            if (plain is null)
            {
                await audit.RecordAsync(User, "file.integrity_or_unavailable", file.Id, "failure");
                Error = "파일을 확인할 수 없습니다. 관리자에게 문의하세요.";
                return Page();
            }
            await files.RecordDownloadAsync("anonymous-share", file.Id, "file.download.started", "success", HttpContext.RequestAborted);
            Response.ContentType = "application/octet-stream";
            Response.ContentLength = plain.Length;
            Response.Headers.ContentDisposition = new ContentDispositionHeaderValue("attachment")
            {
                FileName = "download", FileNameStar = file.OriginalName
            }.ToString();
            try { await Response.Body.WriteAsync(plain, HttpContext.RequestAborted); }
            catch (Exception exception) when (exception is IOException or OperationCanceledException)
            {
                await files.RecordDownloadAsync("anonymous-share", file.Id, "file.download.interrupted", "failure", CancellationToken.None);
                throw;
            }
            await files.RecordDownloadAsync("anonymous-share", file.Id, "file.download.sent", "success", CancellationToken.None);
            return new EmptyResult();
        }
        finally
        {
            if (plain is not null) CryptographicOperations.ZeroMemory(plain);
            gate.Transfer.Release();
        }
    }
}
