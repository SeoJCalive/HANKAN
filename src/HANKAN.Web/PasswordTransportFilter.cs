using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HANKAN.Web;

// Authorization-stage rejection precedes antiforgery's form read and model binding.
public sealed class PasswordTransportFilter : IAsyncAuthorizationFilter, IAsyncResourceFilter, IOrderedFilter
{
    public int Order => int.MinValue;

    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        var http = context.HttpContext;
        if (!HttpMethods.IsPost(http.Request.Method) || AccessModeRuntime.PasswordsAllowed(http)) return;
        var page = (context.ActionDescriptor as PageActionDescriptor)?.ViewEnginePath;
        var forbidden = page is "/Login" or "/Register";
        if (page == "/Shares")
        {
            var handler = http.GetRouteValue("handler")?.ToString();
            forbidden = string.Equals(handler, "Create", StringComparison.OrdinalIgnoreCase) ||
                http.Request.Query["handler"].Any(value => string.Equals(value, "Create", StringComparison.OrdinalIgnoreCase));
        }
        if (page == "/Share")
        {
            var token = http.GetRouteValue("token")?.ToString() ?? "";
            var item = await http.RequestServices.GetRequiredService<ShareStore>().FindActiveAsync(token);
            forbidden = item?.PasswordNeeded == true;
        }
        if (forbidden)
            context.Result = new ContentResult
            {
                StatusCode = StatusCodes.Status403Forbidden,
                ContentType = "text/plain; charset=utf-8",
                Content = AccessModeRuntime.HttpsRequired
            };
    }

    public async Task OnResourceExecutionAsync(ResourceExecutingContext context, ResourceExecutionDelegate next)
    {
        if (!AccessModeRuntime.PasswordsAllowed(context.HttpContext) &&
            (context.ActionDescriptor as PageActionDescriptor)?.ViewEnginePath == "/Share")
        {
            // A password-free HTTP download ignores injected Password/Challenge/Solution fields.
            for (var i = context.ValueProviderFactories.Count - 1; i >= 0; i--)
                if (context.ValueProviderFactories[i] is not RouteValueProviderFactory)
                    context.ValueProviderFactories.RemoveAt(i);
        }
        await next();
    }
}
