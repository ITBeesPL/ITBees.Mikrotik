namespace ITBees.Mikrotik.Api;

public enum RouterOsReplyType
{
    /// <summary>!re - one data item.</summary>
    Data,

    /// <summary>!done - the command finished (may carry =ret=).</summary>
    Done,

    /// <summary>!trap - the command failed.</summary>
    Trap,

    /// <summary>!fatal - the router is closing the connection.</summary>
    Fatal,

    /// <summary>!empty - the command has no data (RouterOS 7.18+); !done follows.</summary>
    Empty,
}

/// <summary>One reply sentence received from the router.</summary>
public sealed class RouterOsReply
{
    private RouterOsReply(RouterOsReplyType type, string? tag, Dictionary<string, string> attributes, IReadOnlyList<string> words)
    {
        Type = type;
        Tag = tag;
        Attributes = attributes;
        Words = words;
    }

    public RouterOsReplyType Type { get; }

    public string? Tag { get; }

    /// <summary>The =name=value words of the sentence.</summary>
    public IReadOnlyDictionary<string, string> Attributes { get; }

    /// <summary>Raw words, including the reply word.</summary>
    public IReadOnlyList<string> Words { get; }

    /// <summary>For !fatal the reason is sent as a bare word rather than =message=.</summary>
    public string? Message =>
        Attributes.TryGetValue("message", out var message) ? message : Type == RouterOsReplyType.Fatal && Words.Count > 1 ? Words[1] : null;

    public static RouterOsReply Parse(IReadOnlyList<string> words)
    {
        if (words.Count == 0)
            throw new FormatException("Empty RouterOS API sentence.");
        var type = words[0] switch
        {
            "!re" => RouterOsReplyType.Data,
            "!done" => RouterOsReplyType.Done,
            "!trap" => RouterOsReplyType.Trap,
            "!fatal" => RouterOsReplyType.Fatal,
            "!empty" => RouterOsReplyType.Empty,
            _ => throw new FormatException($"Unknown RouterOS API reply word '{words[0]}'."),
        };

        string? tag = null;
        var attributes = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 1; i < words.Count; i++)
        {
            var word = words[i];
            if (word.StartsWith(".tag=", StringComparison.Ordinal))
            {
                tag = word[5..];
            }
            else if (word.Length > 1 && word[0] == '=')
            {
                // "=name=value" - the value may contain '=' itself.
                var separator = word.IndexOf('=', 1);
                if (separator < 0)
                    attributes[word[1..]] = string.Empty;
                else
                    attributes[word[1..separator]] = word[(separator + 1)..];
            }
        }
        return new RouterOsReply(type, tag, attributes, words);
    }
}

/// <summary>Everything a command returned: its data items and the attributes of !done (e.g. ret).</summary>
public sealed class RouterOsResponse
{
    public RouterOsResponse(IReadOnlyList<RouterOsRecord> records, IReadOnlyDictionary<string, string> doneAttributes)
    {
        Records = records;
        DoneAttributes = doneAttributes;
    }

    public IReadOnlyList<RouterOsRecord> Records { get; }

    public IReadOnlyDictionary<string, string> DoneAttributes { get; }

    /// <summary>The =ret= value of !done: the new item id after add, the challenge of a legacy login, ...</summary>
    public string? Ret => DoneAttributes.TryGetValue("ret", out var ret) ? ret : null;
}
