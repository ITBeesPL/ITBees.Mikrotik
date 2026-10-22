using System.Text;

namespace ITBees.Mikrotik.Api;

/// <summary>
/// One RouterOS API command, e.g. <c>/ip/address/add =address=10.0.0.1/24 =interface=bridge</c>.
/// Build it fluently: <c>new RouterOsCommand("/ip/address/print").Where("interface", "bridge")</c>.
/// </summary>
public sealed class RouterOsCommand
{
    /// <summary>Attributes whose values are masked in logs and exception messages.</summary>
    public static readonly IReadOnlySet<string> SensitiveAttributes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "password", "private-key", "preshared-key", "pin", "response", "passphrase", "secret",
    };

    private readonly List<KeyValuePair<string, string>> _attributes = new();
    private readonly List<string> _queries = new();
    private readonly List<string> _propList = new();

    public RouterOsCommand(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path[0] != '/')
            throw new ArgumentException("A RouterOS API command starts with '/', e.g. /ip/address/print.", nameof(path));
        Path = path;
    }

    /// <summary>Command path with '/' separators, e.g. /ip/address/add.</summary>
    public string Path { get; }

    public IReadOnlyList<KeyValuePair<string, string>> Attributes => _attributes;

    /// <summary>Query words without the leading '?', e.g. "interface=bridge".</summary>
    public IReadOnlyList<string> Queries => _queries;

    public IReadOnlyList<string> PropList => _propList;

    /// <summary>Adds an attribute (=name=value). A null value is skipped.</summary>
    public RouterOsCommand With(string name, string? value)
    {
        if (value != null)
            _attributes.Add(new KeyValuePair<string, string>(name, value));
        return this;
    }

    public RouterOsCommand With(IEnumerable<KeyValuePair<string, string>> attributes)
    {
        foreach (var attribute in attributes)
            _attributes.Add(attribute);
        return this;
    }

    /// <summary>Adds an equality query (?name=value), used by print commands.</summary>
    public RouterOsCommand Where(string name, string value)
    {
        _queries.Add($"{name}={value}");
        return this;
    }

    /// <summary>Limits the returned properties (=.proplist=a,b,c).</summary>
    public RouterOsCommand Select(params string[] properties)
    {
        _propList.AddRange(properties);
        return this;
    }

    internal IReadOnlyList<string> ToWords(string? tag)
    {
        var words = new List<string>(1 + _attributes.Count + _queries.Count + 2) { Path };
        foreach (var attribute in _attributes)
            words.Add($"={attribute.Key}={attribute.Value}");
        if (_propList.Count > 0)
            words.Add("=.proplist=" + string.Join(",", _propList));
        foreach (var query in _queries)
            words.Add("?" + query);
        if (tag != null)
            words.Add(".tag=" + tag);
        return words;
    }

    /// <summary>The command in RouterOS terminal notation with secrets masked, for logs and dry runs.</summary>
    public string ToCliString()
    {
        var segments = Path.Trim('/').Split('/');
        var sb = new StringBuilder("/");
        sb.Append(string.Join(" ", segments));
        foreach (var attribute in _attributes)
        {
            var name = attribute.Key == ".id" ? "numbers" : attribute.Key;
            var value = SensitiveAttributes.Contains(attribute.Key) ? "***" : attribute.Value;
            sb.Append(' ').Append(name).Append('=').Append(QuoteCli(value));
        }
        if (_queries.Count > 0)
            sb.Append(" where ").Append(string.Join(" && ", _queries.Select(q => QuoteQuery(q))));
        return sb.ToString();
    }

    public override string ToString() => ToCliString();

    private static string QuoteQuery(string query)
    {
        var index = query.IndexOf('=');
        return index < 0 ? query : query[..(index + 1)] + QuoteCli(query[(index + 1)..]);
    }

    private static string QuoteCli(string value)
    {
        if (value.Length > 0 && value.All(c => char.IsLetterOrDigit(c) || c is '.' or ',' or ':' or '/' or '-' or '_' or '*' or '@'))
            return value;
        var escaped = value.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("$", "\\$").Replace("\n", "\\n").Replace("\r", "\\r");
        return "\"" + escaped + "\"";
    }
}
