using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Net.Http.Headers;

namespace HANKAN.Web.Pages;

public sealed class FilesModel(AccessStore access, FileStore files, FolderStore folders, FileTransferGate gate, SignInManager<AppUser> signIn, AuditStore audit) : PageModel
{
    public AccountAccess? Current { get; private set; }
    public List<StoredFile> Items { get; private set; } = [];
    public FolderView? Folder { get; private set; }
    public List<StoredFile> DeletingItems { get; private set; } = [];
    public long UsedBytes { get; private set; }
    public long QuotaBytes { get; private set; }
    public string? DeleteMessage { get; private set; }

    public async Task<IActionResult> OnGetAsync(string? folderId)
    {
        if (Request.Query.ContainsKey("folderId") && folderId is null) return NotFound();
        Current = await access.CurrentAsync(User);
        if (Current is null) return RedirectToPage("/Login");
        if (!await LoadAsync(folderId)) return NotFound();
        return Page();
    }

    public async Task<IActionResult> OnPostDeleteAsync(string id, string? confirmation, string? folderId)
    {
        Current = await access.CurrentAsync(User);
        if (Current is null || !Current.IsAdmin && Current.State != "owner")
        {
            await audit.RecordAsync(User, "file.delete", id, "denied");
            return StatusCode(403);
        }
        if (await folders.ReadAsync(folderId) is null) return BadRequest("올바른 폴더를 선택하세요.");
        if (confirmation != "delete") DeleteMessage = "복원 불가와 연결 공유 무효화를 확인하세요.";
        else
        {
            var actorId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (actorId is null) return StatusCode(403);
            var result = await files.DeleteAsync(id, actorId);
            if (result == FileDeleteResult.Forbidden)
            {
                await audit.RecordAsync(User, "file.delete", null, "denied");
                return StatusCode(403);
            }
            if (result == FileDeleteResult.Deleted) return Redirect(FolderUrl(folderId));
            DeleteMessage = result switch
            {
                FileDeleteResult.Deleted => "파일과 연결 공유를 영구 삭제했습니다.",
                FileDeleteResult.RetryNeeded => "삭제 처리 중입니다. 완료되지 않아 재시도가 필요합니다.",
                _ => "삭제할 수 있는 파일을 찾을 수 없습니다."
            };
        }
        if (!await LoadAsync(folderId)) return BadRequest("올바른 폴더를 선택하세요.");
        return Page();
    }

    public Task<IActionResult> OnPostCreateFolderAsync(string? folderId, string? name) =>
        ChangeFolderAsync("create", folderId, null, name, null);

    public Task<IActionResult> OnPostRenameFolderAsync(string? folderId, string? id, string? name) =>
        ChangeFolderAsync("rename", folderId, id, name, null);

    public Task<IActionResult> OnPostMoveFolderAsync(string? folderId, string? id, string? destinationId) =>
        ChangeFolderAsync("move", folderId, id, null, destinationId);

    public Task<IActionResult> OnPostDeleteFolderAsync(string? folderId, string? id) =>
        ChangeFolderAsync("delete", folderId, id, null, null);

    public Task<IActionResult> OnPostRenameFileAsync(string? folderId, string? id, string? name) =>
        ChangeFileAsync("rename", folderId, id, name, null);

    public Task<IActionResult> OnPostMoveFileAsync(string? folderId, string? id, string? destinationId) =>
        ChangeFileAsync("move", folderId, id, null, destinationId);

    private async Task<IActionResult> ChangeFolderAsync(string action, string? folderId, string? id, string? name, string? destinationId)
    {
        var current = await access.CurrentAsync(User);
        if (current is null || !current.IsAdmin && current.State != "owner")
        {
            await audit.RecordAsync(User, "folder." + action, id, "denied");
            return StatusCode(403);
        }
        if (await folders.ReadAsync(folderId) is null) return BadRequest("올바른 폴더를 선택하세요.");
        var actorId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (actorId is null) return StatusCode(403);
        var result = action switch
        {
            "create" => await folders.CreateAsync(folderId, name, actorId),
            "rename" => await folders.RenameAsync(id ?? "", name, actorId),
            "move" => await folders.MoveAsync(id ?? "", destinationId, actorId),
            "delete" => await folders.DeleteAsync(id ?? "", actorId),
            _ => FolderChangeResult.Invalid
        };
        return result switch
        {
            FolderChangeResult.Success => Redirect(FolderUrl(folderId)),
            FolderChangeResult.Forbidden => StatusCode(403),
            _ => BadRequest("폴더 작업을 완료할 수 없습니다. 이름·위치·내용을 확인하세요.")
        };
    }

    private async Task<IActionResult> ChangeFileAsync(string action, string? folderId, string? id, string? name, string? destinationId)
    {
        var current = await access.CurrentAsync(User);
        if (current is null || !current.IsAdmin && current.State != "owner")
        {
            await audit.RecordAsync(User, "file." + action, id, "denied");
            return StatusCode(403);
        }
        if (await folders.ReadAsync(folderId) is null) return BadRequest("올바른 폴더를 선택하세요.");
        var actorId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (actorId is null) return StatusCode(403);
        var result = action switch
        {
            "rename" => await files.RenameAsync(id ?? "", name, actorId),
            "move" => await files.MoveAsync(id ?? "", destinationId, actorId),
            _ => FileChangeResult.Invalid
        };
        return result switch
        {
            FileChangeResult.Success => Redirect(FolderUrl(folderId)),
            FileChangeResult.Forbidden => StatusCode(403),
            _ => BadRequest("파일 이름이나 이동 위치를 확인하세요.")
        };
    }

    private static string FolderUrl(string? id) => id is null ? "/Files" : "/Files?folderId=" + id;

    private async Task<bool> LoadAsync(string? folderId)
    {
        Folder = await folders.ReadAsync(folderId);
        if (Folder is null) return false;
        Items = await files.ListAsync(folderId);
        if (Current?.IsAdmin == true || Current?.State == "owner")
            DeletingItems = await files.ListDeletingAsync();
        (UsedBytes, QuotaBytes) = await files.UsageAsync();
        return true;
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
