using System.Globalization;
using System.Text.RegularExpressions;

namespace ITBees.Mikrotik.Api;

/// <summary>RouterOS version parsed from "7.16.2 (stable)", "7.19beta3 (testing)" or "6.49.10 (long-term)".</summary>
public sealed record RouterOsVersion(int Major, int Minor, int Patch, string Raw) : IComparable<RouterOsVersion>
{
    private static readonly Regex Pattern = new(@"^\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?", RegexOptions.Compiled);

    /// <summary>Channel from the parentheses, e.g. "stable" or "long-term"; null when absent.</summary>
    public string? Channel
    {
        get
        {
            var open = Raw.IndexOf('(');
            var close = Raw.IndexOf(')');
            return open >= 0 && close > open ? Raw[(open + 1)..close] : null;
        }
    }

    public static bool TryParse(string? value, out RouterOsVersion version)
    {
        version = new RouterOsVersion(0, 0, 0, value ?? string.Empty);
        if (string.IsNullOrWhiteSpace(value))
            return false;
        var match = Pattern.Match(value);
        if (!match.Success)
            return false;
        version = new RouterOsVersion(
            int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture),
            match.Groups[2].Success ? int.Parse(match.Groups[2].Value, CultureInfo.InvariantCulture) : 0,
            match.Groups[3].Success ? int.Parse(match.Groups[3].Value, CultureInfo.InvariantCulture) : 0,
            value.Trim());
        return true;
    }

    public bool IsAtLeast(int major, int minor = 0, int patch = 0) =>
        CompareTo(new RouterOsVersion(major, minor, patch, string.Empty)) >= 0;

    public int CompareTo(RouterOsVersion? other)
    {
        if (other is null)
            return 1;
        var c = Major.CompareTo(other.Major);
        if (c != 0)
            return c;
        c = Minor.CompareTo(other.Minor);
        return c != 0 ? c : Patch.CompareTo(other.Patch);
    }

    public override string ToString() => Raw.Length > 0 ? Raw : $"{Major}.{Minor}.{Patch}";
}
