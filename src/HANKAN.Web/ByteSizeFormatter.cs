using System.Globalization;

namespace HANKAN.Web;

public static class ByteSizeFormatter
{
    private static readonly string[] Units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];

    public static (string Short, string? Exact) Format(long? bytes)
    {
        if (bytes is not long value || value < 0) return ("—", null);
        var unit = 0;
        long scale = 1;
        while (value / scale >= 1024) { scale *= 1024; unit++; }
        // Keep the half-way decision exact even near long.MaxValue.
        var tenths = ((decimal)value * 10 + scale / 2) / scale;
        var rounded = decimal.Floor(tenths) / 10;
        if (rounded == 1024) { rounded = 1; unit++; }
        return (rounded.ToString("0.#", CultureInfo.InvariantCulture) + " " + Units[unit],
            value.ToString("N0", CultureInfo.InvariantCulture) + " 바이트");
    }
}
