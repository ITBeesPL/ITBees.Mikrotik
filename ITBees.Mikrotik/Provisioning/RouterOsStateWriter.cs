using ITBees.Mikrotik.Api;
using Microsoft.Extensions.Logging;

namespace ITBees.Mikrotik.Provisioning;

/// <summary>Ordered property list for add/set commands; null values are skipped.</summary>
internal sealed class Props : List<KeyValuePair<string, string>>
{
    public void Add(string name, string? value)
    {
        if (value != null)
            Add(new KeyValuePair<string, string>(name, value));
    }

    public string? Get(string name) => this.FirstOrDefault(kv => kv.Key == name).Value;
}

/// <summary>
/// Idempotent writes: every object is located by a key (name, interface, or an "itbees:" comment), created when
/// missing, updated only where it differs, and duplicates are removed. In a dry run nothing is written and the
/// planned commands are recorded instead.
/// </summary>
internal sealed class RouterOsStateWriter
{
    public const string CommentPrefix = "itbees:";

    private readonly IRouterOsApiConnection _api;
    private readonly ILogger _logger;
    private int _dryRunIds;

    public RouterOsStateWriter(IRouterOsApiConnection api, bool dryRun, ILogger logger)
    {
        _api = api;
        DryRun = dryRun;
        _logger = logger;
    }

    public bool DryRun { get; }

    public string Step { get; set; } = string.Empty;

    public List<MikrotikConfigurationChange> Changes { get; } = new();

    public IRouterOsApiConnection Api => _api;

    public async Task<IReadOnlyList<RouterOsRecord>> PrintAsync(string menu, CancellationToken cancellationToken, params (string Name, string Value)[] where)
    {
        var command = new RouterOsCommand(menu + "/print");
        foreach (var (name, value) in where)
            command.Where(name, value);
        return (await _api.ExecuteAsync(command, cancellationToken).ConfigureAwait(false)).Records;
    }

    public async Task<RouterOsRecord?> GetSingletonAsync(string menu, CancellationToken cancellationToken) =>
        (await PrintAsync(menu, cancellationToken).ConfigureAwait(false)).FirstOrDefault();

    public async Task<string> AddAsync(string menu, Props values, string description, CancellationToken cancellationToken)
    {
        var command = new RouterOsCommand(menu + "/add").With(values);
        Record(MikrotikChangeAction.Add, menu, description, command);
        if (DryRun)
            return $"*dry{++_dryRunIds}";
        var response = await _api.ExecuteAsync(command, cancellationToken).ConfigureAwait(false);
        return response.Ret ?? string.Empty;
    }

    public async Task SetAsync(string menu, string id, Props values, string description, CancellationToken cancellationToken)
    {
        if (values.Count == 0)
            return;
        var command = new RouterOsCommand(menu + "/set").With(".id", id).With(values);
        Record(MikrotikChangeAction.Set, menu, description, command);
        if (!DryRun)
            await _api.ExecuteAsync(command, cancellationToken).ConfigureAwait(false);
    }

    public async Task RemoveAsync(string menu, string id, string description, CancellationToken cancellationToken)
    {
        var command = new RouterOsCommand(menu + "/remove").With(".id", id);
        Record(MikrotikChangeAction.Remove, menu, description, command);
        if (!DryRun)
            await _api.ExecuteAsync(command, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Moves item <paramref name="id"/> right before <paramref name="beforeId"/>.</summary>
    public async Task MoveAsync(string menu, string id, string beforeId, string description, CancellationToken cancellationToken)
    {
        var command = new RouterOsCommand(menu + "/move").With("numbers", id).With("destination", beforeId);
        Record(MikrotikChangeAction.Move, menu, description, command);
        if (!DryRun)
            await _api.ExecuteAsync(command, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Sets the properties of a singleton menu (/system/identity, /ip/dns, ...) that differ.</summary>
    public async Task<bool> EnsureSingletonAsync(string menu, Props desired, string description, CancellationToken cancellationToken)
    {
        var current = await GetSingletonAsync(menu, cancellationToken).ConfigureAwait(false);
        var diff = Diff(current, desired);
        if (diff.Count == 0)
            return false;
        var command = new RouterOsCommand(menu + "/set").With(diff);
        Record(MikrotikChangeAction.Set, menu, description, command);
        if (!DryRun)
            await _api.ExecuteAsync(command, cancellationToken).ConfigureAwait(false);
        return true;
    }

    /// <summary>
    /// Makes sure exactly one item matching <paramref name="match"/> exists with the desired properties.
    /// <paramref name="addOnly"/> are only used when the item is created (e.g. a comment on a factory bridge).
    /// Returns the item id.
    /// </summary>
    public async Task<string> EnsureAsync(
        string menu,
        (string Name, string Value)[] match,
        Props desired,
        string description,
        CancellationToken cancellationToken,
        Props? addOnly = null,
        bool removeDuplicates = true)
    {
        var rows = (await PrintAsync(menu, cancellationToken, match).ConfigureAwait(false))
            .Where(r => !r.IsDynamic)
            .ToList();

        if (rows.Count == 0)
        {
            var values = new Props();
            values.AddRange(desired);
            if (addOnly != null)
                values.AddRange(addOnly.Where(kv => desired.Get(kv.Key) == null));
            return await AddAsync(menu, values, description, cancellationToken).ConfigureAwait(false);
        }

        var item = rows[0];
        var diff = Diff(item, desired);
        if (diff.Count > 0)
            await SetAsync(menu, item.Id!, diff, description, cancellationToken).ConfigureAwait(false);
        if (removeDuplicates)
        {
            foreach (var duplicate in rows.Skip(1))
                await RemoveAsync(menu, duplicate.Id!, $"{description} (duplicate)", cancellationToken).ConfigureAwait(false);
        }
        return item.Id!;
    }

    /// <summary>Removes static items whose comment starts with <paramref name="commentPrefix"/> and is not in <paramref name="keep"/>.</summary>
    public async Task<int> RemoveStaleAsync(string menu, string commentPrefix, IReadOnlyCollection<string> keep, string description, CancellationToken cancellationToken)
    {
        var removed = 0;
        foreach (var row in await PrintAsync(menu, cancellationToken).ConfigureAwait(false))
        {
            var comment = row.Comment;
            if (row.IsDynamic || comment == null || !comment.StartsWith(commentPrefix, StringComparison.Ordinal) || keep.Contains(comment))
                continue;
            await RemoveAsync(menu, row.Id!, $"{description} ({comment})", cancellationToken).ConfigureAwait(false);
            removed++;
        }
        return removed;
    }

    public static Props Diff(RouterOsRecord? current, Props desired)
    {
        var diff = new Props();
        foreach (var (name, value) in desired)
        {
            if (current == null || !RouterOsValues.AreEquivalent(current.Get(name), value))
                diff.Add(name, value);
        }
        return diff;
    }

    private void Record(MikrotikChangeAction action, string menu, string description, RouterOsCommand command)
    {
        var change = new MikrotikConfigurationChange(Step, action, menu, description, command.ToCliString());
        Changes.Add(change);
        _logger.LogInformation("{Prefix}{Change}", DryRun ? "[dry run] " : string.Empty, change);
    }
}
