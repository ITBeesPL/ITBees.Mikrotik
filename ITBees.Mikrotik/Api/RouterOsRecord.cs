using System.Collections;
using System.Globalization;

namespace ITBees.Mikrotik.Api;

/// <summary>One item returned by a print command (one !re sentence): property name to value.</summary>
public sealed class RouterOsRecord : IReadOnlyDictionary<string, string>
{
    private readonly Dictionary<string, string> _values;

    public RouterOsRecord(IDictionary<string, string> values)
    {
        _values = new Dictionary<string, string>(values, StringComparer.Ordinal);
    }

    /// <summary>Internal item id (".id"), e.g. "*1A". Null for singleton menus such as /system/identity.</summary>
    public string? Id => Get(".id");

    public string? Comment => Get("comment");

    public bool IsDynamic => GetBool("dynamic") == true;

    public bool IsDisabled => GetBool("disabled") == true;

    public string? Get(string name) => _values.TryGetValue(name, out var value) ? value : null;

    /// <summary>Parses "true"/"false"/"yes"/"no"; null when missing or not a boolean.</summary>
    public bool? GetBool(string name) => RouterOsValues.ParseBool(Get(name));

    public long? GetLong(string name) =>
        long.TryParse(Get(name), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? value : null;

    /// <summary>Parses RouterOS durations such as "1m25s", "1d2h", "00:03:00" or "3w2d10:00:01".</summary>
    public TimeSpan? GetDuration(string name) => RouterOsValues.ParseDuration(Get(name));

    public string this[string key] => _values[key];

    public IEnumerable<string> Keys => _values.Keys;

    public IEnumerable<string> Values => _values.Values;

    public int Count => _values.Count;

    public bool ContainsKey(string key) => _values.ContainsKey(key);

    public bool TryGetValue(string key, out string value) => _values.TryGetValue(key, out value!);

    public IEnumerator<KeyValuePair<string, string>> GetEnumerator() => _values.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    public override string ToString() => string.Join(" ", _values.Select(kv => $"{kv.Key}={kv.Value}"));
}

/// <summary>Parsing and comparison of RouterOS property values.</summary>
public static class RouterOsValues
{
    public static bool? ParseBool(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "true" or "yes" => true,
        "false" or "no" => false,
        _ => null,
    };

    /// <summary>Formats a boolean the way the API accepts it.</summary>
    public static string Bool(bool value) => value ? "yes" : "no";

    /// <summary>Formats a duration as RouterOS understands it (e.g. 25s, 1m30s, 1d).</summary>
    public static string Duration(TimeSpan value)
    {
        if (value <= TimeSpan.Zero)
            return "0s";
        var parts = new System.Text.StringBuilder();
        if (value.Days >= 7)
            parts.Append(value.Days / 7).Append('w');
        if (value.Days % 7 > 0)
            parts.Append(value.Days % 7).Append('d');
        if (value.Hours > 0)
            parts.Append(value.Hours).Append('h');
        if (value.Minutes > 0)
            parts.Append(value.Minutes).Append('m');
        if (value.Seconds > 0)
            parts.Append(value.Seconds).Append('s');
        if (value.Milliseconds > 0)
            parts.Append(value.Milliseconds).Append("ms");
        return parts.ToString();
    }

    public static TimeSpan? ParseDuration(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        value = value.Trim();

        // "hh:mm:ss" (optionally prefixed with "3w2d") as printed by RouterOS v6 and some v7 menus.
        var total = TimeSpan.Zero;
        var number = 0L;
        var hasNumber = false;
        var i = 0;
        while (i < value.Length)
        {
            var c = value[i];
            if (char.IsDigit(c))
            {
                number = number * 10 + (c - '0');
                hasNumber = true;
                i++;
                continue;
            }
            if (c == ':' || c == '.')
            {
                var clock = value[(i - CountDigitsBefore(value, i))..];
                if (TimeSpan.TryParseExact(clock, new[] { @"hh\:mm\:ss", @"hh\:mm\:ss\.fff", @"h\:mm\:ss" }, CultureInfo.InvariantCulture, out var parsed))
                    return total + parsed;
                return null;
            }
            if (!hasNumber)
                return null;
            if (c == 'm' && i + 1 < value.Length && value[i + 1] == 's')
            {
                total += TimeSpan.FromMilliseconds(number);
                i += 2;
            }
            else if (c == 'u' && i + 1 < value.Length && value[i + 1] == 's')
            {
                total += TimeSpan.FromTicks(number * 10);
                i += 2;
            }
            else
            {
                total += c switch
                {
                    'w' => TimeSpan.FromDays(7 * number),
                    'd' => TimeSpan.FromDays(number),
                    'h' => TimeSpan.FromHours(number),
                    'm' => TimeSpan.FromMinutes(number),
                    's' => TimeSpan.FromSeconds(number),
                    _ => TimeSpan.MinValue,
                };
                if (total < TimeSpan.Zero)
                    return null;
                i++;
            }
            number = 0;
            hasNumber = false;
        }
        if (hasNumber)
            total += TimeSpan.FromSeconds(number);
        return total;
    }

    /// <summary>
    /// Compares a value read from the router with the value we want to set, tolerating the usual
    /// RouterOS normalisations (yes/true, 25s/00:00:25, spaces in lists). A false negative only
    /// causes a redundant (harmless) set command.
    /// </summary>
    public static bool AreEquivalent(string? current, string desired)
    {
        current ??= string.Empty;
        if (string.Equals(current, desired, StringComparison.Ordinal))
            return true;
        var currentBool = ParseBool(current);
        var desiredBool = ParseBool(desired);
        if (currentBool != null && desiredBool != null)
            return currentBool == desiredBool;
        if (LooksLikeDuration(desired) && LooksLikeDuration(current))
        {
            var a = ParseDuration(current);
            var b = ParseDuration(desired);
            if (a != null && b != null)
                return a == b;
        }
        if (desired.Contains(',') || current.Contains(','))
            return string.Equals(NormalizeList(current), NormalizeList(desired), StringComparison.Ordinal);
        return false;
    }

    private static bool LooksLikeDuration(string value) =>
        value.Length > 0 && char.IsDigit(value[0]) && (value.EndsWith('s') || value.EndsWith('m') || value.EndsWith('h') || value.EndsWith('d') || value.EndsWith('w') || value.Count(c => c == ':') == 2);

    private static string NormalizeList(string value) =>
        string.Join(",", value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries));

    private static int CountDigitsBefore(string value, int index)
    {
        var count = 0;
        while (index - count - 1 >= 0 && char.IsDigit(value[index - count - 1]))
            count++;
        return count;
    }
}
