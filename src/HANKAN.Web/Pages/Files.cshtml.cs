using System.Security.Claims;
using System.Security.Cryptography;
using System.IO.Compression;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Net.Http.Headers;

namespace HANKAN.Web.Pages;

public sealed class FilesModel(AccessStore access, FileStore files, FolderStore folders, SelectionResolver selection, BulkMoveStore bulkMove, BulkDeleteStore bulkDelete, FileTransferGate gate, SignInManager<AppUser> signIn, AuditStore audit, ILogger<FilesModel> logger) : PageModel
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

    public async Task<IActionResult> OnPostSelectionSummaryAsync()
    {
        if (!Request.HasFormContentType || Request.ContentType is null ||
            !Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
            return SelectionError(400, "invalid_selection", "선택 요청 형식을 확인하세요.");

        await gate.Transfer.WaitAsync(HttpContext.RequestAborted);
        try
        {
            var current = await access.CurrentAsync(User);
            if (current is null || !current.IsAdmin && current.State is not ("viewer" or "owner"))
                return SelectionError(403, "forbidden", "선택 항목에 접근할 권한이 없습니다.");

            var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
            var folderValues = form["folderId"];
            if (folderValues.Count > 1)
                return SelectionError(400, "invalid_selection", "선택 항목을 다시 확인하세요.");
            var folderId = folderValues.Count == 0 || folderValues[0] == "" ? null : folderValues[0];
            var scope = await selection.ResolveAsync(folderId, form["folderIds"].Select(id => id ?? "").ToArray(),
                form["fileIds"].Select(id => id ?? "").ToArray(), HttpContext.RequestAborted);
            if (scope is null)
                return SelectionError(400, "invalid_selection", "선택 항목을 다시 확인하세요.");

            return new JsonResult(new
            {
                directCount = scope.DirectCount,
                folderCount = scope.Folders.Count,
                fileCount = scope.Files.Count
            });
        }
        finally { gate.Transfer.Release(); }
    }

    private static JsonResult SelectionError(int status, string code, string message) =>
        new(new { code, message }) { StatusCode = status };

    public async Task<IActionResult> OnPostDeletePreviewAsync()
    {
        if (!Request.HasFormContentType || Request.ContentType is null ||
            !Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
            return SelectionError(400, "invalid_selection", "선택 요청 형식을 확인하세요.");
        var current = await access.CurrentAsync(User);
        if (current is null || !current.IsAdmin && current.State != "owner")
        {
            await audit.RecordAsync(User, "selection.delete.preview", null, "denied");
            return SelectionError(403, "forbidden", "삭제 권한이 없습니다.");
        }
        var actorId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (actorId is null) return SelectionError(403, "forbidden", "삭제 권한이 없습니다.");
        IFormCollection form;
        try { form = await Request.ReadFormAsync(HttpContext.RequestAborted); }
        catch (InvalidDataException) { return SelectionError(400, "invalid_selection", "선택 요청 형식을 확인하세요."); }
        if (form["folderId"].Count > 1) return SelectionError(400, "invalid_selection", "선택 항목을 다시 확인하세요.");
        var folderId = form["folderId"].Count == 0 || form["folderId"][0] == "" ? null : form["folderId"][0];
        var (result, impact) = await bulkDelete.PreviewAsync(actorId, folderId,
            form["folderIds"].Select(id => id ?? "").ToArray(),
            form["fileIds"].Select(id => id ?? "").ToArray(), HttpContext.RequestAborted);
        return result switch
        {
            BulkDeleteResult.Success => new JsonResult(new
            {
                directCount = impact!.DirectCount, folderCount = impact.FolderCount,
                fileCount = impact.FileCount, totalBytes = impact.TotalBytes,
                shareCount = impact.ShareCount, irreversible = true, previewToken = impact.PreviewToken
            }),
            BulkDeleteResult.Forbidden => SelectionError(403, "forbidden", "삭제 권한이 없습니다."),
            _ => SelectionError(400, "invalid_selection", "선택 항목을 다시 확인하세요.")
        };
    }

    public async Task<IActionResult> OnPostDeleteSelectionAsync()
    {
        if (!Request.HasFormContentType || Request.ContentType is null ||
            !Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
            return SelectionError(400, "invalid_selection", "선택 요청 형식을 확인하세요.");
        var current = await access.CurrentAsync(User);
        if (current is null || !current.IsAdmin && current.State != "owner")
        {
            await audit.RecordAsync(User, "selection.delete", null, "denied");
            return SelectionError(403, "forbidden", "삭제 권한이 없습니다.");
        }
        var actorId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (actorId is null) return SelectionError(403, "forbidden", "삭제 권한이 없습니다.");
        IFormCollection form;
        try { form = await Request.ReadFormAsync(HttpContext.RequestAborted); }
        catch (InvalidDataException) { return SelectionError(400, "invalid_selection", "선택 요청 형식을 확인하세요."); }
        if (form["folderId"].Count > 1 || form["previewToken"].Count != 1 ||
            string.IsNullOrWhiteSpace(form["previewToken"][0]))
            return SelectionError(400, "invalid_selection", "확인 요청 형식을 확인하세요.");
        var folderId = form["folderId"].Count == 0 || form["folderId"][0] == "" ? null : form["folderId"][0];
        var (result, outcome) = await bulkDelete.DeleteAsync(actorId, folderId,
            form["folderIds"].Select(id => id ?? "").ToArray(),
            form["fileIds"].Select(id => id ?? "").ToArray(), form["previewToken"][0]!,
            HttpContext.RequestAborted);
        return result switch
        {
            BulkDeleteResult.Success => new JsonResult(new
            {
                deletedFileCount = outcome!.DeletedFileCount, retryFileCount = outcome.RetryFileCount,
                deletedFolderCount = outcome.DeletedFolderCount,
                remainingFolderCount = outcome.RemainingFolderCount, partial = outcome.Partial
            }),
            BulkDeleteResult.Forbidden => SelectionError(403, "forbidden", "삭제 권한이 없습니다."),
            BulkDeleteResult.Changed => SelectionError(409, "delete_changed", "삭제 영향이 바뀌었거나 확인이 만료되었습니다. 다시 확인하세요."),
            _ => SelectionError(400, "invalid_selection", "선택 항목을 다시 확인하세요.")
        };
    }

    public async Task<IActionResult> OnPostMoveSelectionAsync()
    {
        if (!Request.HasFormContentType || Request.ContentType is null ||
            !Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
            return SelectionError(400, "invalid_selection", "선택 요청 형식을 확인하세요.");

        var current = await access.CurrentAsync(User);
        if (current is null || !current.IsAdmin && current.State != "owner")
        {
            await audit.RecordAsync(User, "selection.move", null, "denied");
            return SelectionError(403, "forbidden", "이동 권한이 없습니다.");
        }
        var actorId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (actorId is null) return SelectionError(403, "forbidden", "이동 권한이 없습니다.");

        IFormCollection form;
        try { form = await Request.ReadFormAsync(HttpContext.RequestAborted); }
        catch (InvalidDataException) { return SelectionError(400, "invalid_selection", "선택 요청 형식을 확인하세요."); }
        var sourceValues = form["folderId"];
        var destinationValues = form["destinationId"];
        if (sourceValues.Count > 1 || destinationValues.Count != 1)
            return SelectionError(400, "invalid_selection", "선택 항목과 목적지를 다시 확인하세요.");
        var sourceId = sourceValues.Count == 0 || sourceValues[0] == "" ? null : sourceValues[0];
        var destinationId = destinationValues[0] == "" ? null : destinationValues[0];
        var (result, movedCount) = await bulkMove.MoveAsync(actorId, sourceId,
            form["folderIds"].Select(id => id ?? "").ToArray(),
            form["fileIds"].Select(id => id ?? "").ToArray(), destinationId, HttpContext.RequestAborted);
        return result switch
        {
            BulkMoveResult.Success => new JsonResult(new { movedCount }),
            BulkMoveResult.Forbidden => SelectionError(403, "forbidden", "이동 권한이 없습니다."),
            BulkMoveResult.SameLocation => SelectionError(409, "move_conflict", "이미 같은 위치에 있습니다."),
            BulkMoveResult.Descendant => SelectionError(409, "move_conflict", "선택한 폴더 자신이나 하위 폴더로 이동할 수 없습니다."),
            BulkMoveResult.NameCollision => SelectionError(409, "move_conflict", "목적지에 같은 이름의 폴더가 있습니다."),
            BulkMoveResult.MissingDestination => SelectionError(409, "move_conflict", "목적지 폴더가 사라졌습니다. 다시 선택하세요."),
            _ => SelectionError(400, "invalid_selection", "선택 항목과 목적지를 다시 확인하세요.")
        };
    }

    public async Task<IActionResult> OnPostDownloadSelectionAsync()
    {
        if (!Request.HasFormContentType || Request.ContentType is null ||
            !Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
            return SelectionError(400, "invalid_selection", "선택 요청 형식을 확인하세요.");

        await gate.Transfer.WaitAsync(HttpContext.RequestAborted);
        try
        {
            var current = await access.CurrentAsync(User);
            if (current is null || !current.IsAdmin && current.State is not ("viewer" or "owner"))
                return SelectionError(403, "forbidden", "다운로드 권한이 없습니다.");
            var actorId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (actorId is null) return SelectionError(403, "forbidden", "다운로드 권한이 없습니다.");

            IFormCollection form;
            try { form = await Request.ReadFormAsync(HttpContext.RequestAborted); }
            catch (InvalidDataException)
            {
                return SelectionError(400, "invalid_selection", "선택 요청 형식을 확인하세요.");
            }
            var folderValues = form["folderId"];
            if (folderValues.Count > 1)
                return SelectionError(400, "invalid_selection", "선택 항목을 다시 확인하세요.");
            var folderId = folderValues.Count == 0 || folderValues[0] == "" ? null : folderValues[0];
            var scope = await selection.ResolveAsync(folderId, form["folderIds"].Select(id => id ?? "").ToArray(),
                form["fileIds"].Select(id => id ?? "").ToArray(), HttpContext.RequestAborted);
            if (scope is null) return SelectionError(400, "invalid_selection", "선택 항목을 다시 확인하세요.");

            var plan = SelectionZipArchive.Plan(scope);
            if (plan.Status == SelectionZipStatus.Invalid)
                return SelectionError(400, "invalid_selection", "선택 항목이나 ZIP 경로를 다시 확인하세요.");
            if (plan.Status == SelectionZipStatus.TooLarge)
                return SelectionError(413, "zip_limit", "ZIP은 1,000개 항목과 원본 500,000,000바이트까지 받을 수 있습니다.");

            try
            {
                Response.ContentType = "application/zip";
                Response.Headers.CacheControl = "no-store";
                Response.Headers.XContentTypeOptions = "nosniff";
                Response.Headers.ContentDisposition = new ContentDispositionHeaderValue("attachment")
                {
                    FileNameStar = "HANKAN-selection.zip"
                }.ToString();
                var bodyControl = HttpContext.Features.Get<IHttpBodyControlFeature>();
                var previousSynchronousIO = bodyControl?.AllowSynchronousIO ?? false;
                if (bodyControl is not null) bodyControl.AllowSynchronousIO = true;
                try
                {
                    await using var archive = await ZipArchive.CreateAsync(Response.Body, ZipArchiveMode.Create,
                        leaveOpen: true, entryNameEncoding: null, cancellationToken: HttpContext.RequestAborted);
                    foreach (var item in plan.Entries)
                    {
                        HttpContext.RequestAborted.ThrowIfCancellationRequested();
                        if (item.File is null)
                        {
                            archive.CreateEntry(item.Path);
                            continue;
                        }
                        byte[]? plain = null;
                        try
                        {
                            plain = await files.DecryptAsync(item.File, HttpContext.RequestAborted);
                            if (plain is null || plain.LongLength != item.File.SizeBytes)
                                throw new InvalidDataException("Selected file cannot be authenticated.");
                            var entry = archive.CreateEntry(item.Path);
                            await using var output = entry.Open();
                            await output.WriteAsync(plain, HttpContext.RequestAborted);
                        }
                        finally { if (plain is not null) CryptographicOperations.ZeroMemory(plain); }
                    }
                }
                finally { if (bodyControl is not null) bodyControl.AllowSynchronousIO = previousSynchronousIO; }
                await audit.RecordAsync(actorId, "selection.download", null, "success");
                return new EmptyResult();
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Selected ZIP download failed for {ActorId}", actorId);
                try { await audit.RecordAsync(actorId, "selection.download", null, "failure"); }
                catch (Exception auditException) { logger.LogError(auditException, "Selected ZIP failure audit failed"); }
                if (Response.HasStarted || HttpContext.RequestAborted.IsCancellationRequested)
                {
                    HttpContext.Abort();
                    return new EmptyResult();
                }
                Response.Headers.Remove("Content-Disposition");
                Response.Headers.Remove("Cache-Control");
                Response.ContentType = "application/json";
                return SelectionError(400, "download_failed", "ZIP을 만들 수 없습니다. 저장소 상태를 확인하세요.");
            }
        }
        finally { gate.Transfer.Release(); }
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
