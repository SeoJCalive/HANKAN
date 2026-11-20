using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HANKAN.Web;

public sealed class PasswordTransportFilter : IAsyncResourceFilter, IOrderedFilter
{
    public int Order => int.MinValue;

    // Called after endpoint selection, before authentication/authorization and antiforgery.
    public static async Task<bool> RequiresHttpsAsync(HttpContext http, PageActionDescriptor? descriptor)
    {
        if (!HttpMethods.IsPost(http.Request.Method) || AccessModeRuntime.PasswordsAllowed(http)) return false;
        var page = descriptor?.ViewEnginePath;
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
        return forbidden;
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
