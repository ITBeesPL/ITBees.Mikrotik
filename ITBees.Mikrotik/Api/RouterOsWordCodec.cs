using System.Text;

namespace ITBees.Mikrotik.Api;

/// <summary>
/// RouterOS API wire format: a sentence is a list of length-prefixed words terminated by an empty word.
/// The length prefix uses 1-5 bytes depending on the value (see the RouterOS API manual).
/// </summary>
internal static class RouterOsWordCodec
{
    /// <summary>Upper bound for a single word; protects against corrupted streams.</summary>
    public const int MaxWordLength = 16 * 1024 * 1024;

    public static readonly Encoding Encoding = new UTF8Encoding(false);

    public static byte[] EncodeLength(int length)
    {
        if (length < 0)
            throw new ArgumentOutOfRangeException(nameof(length));
        if (length < 0x80)
            return new[] { (byte)length };
        if (length < 0x4000)
        {
            var v = length | 0x8000;
            return new[] { (byte)(v >> 8), (byte)v };
        }
        if (length < 0x200000)
        {
            var v = length | 0xC00000;
            return new[] { (byte)(v >> 16), (byte)(v >> 8), (byte)v };
        }
        if (length < 0x10000000)
        {
            var v = (uint)length | 0xE0000000;
            return new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v };
        }
        return new byte[] { 0xF0, (byte)(length >> 24), (byte)(length >> 16), (byte)(length >> 8), (byte)length };
    }

    /// <summary>Decodes a length prefix from a buffer; returns the number of bytes consumed or 0 when more data is needed.</summary>
    public static int DecodeLength(ReadOnlySpan<byte> data, out int length)
    {
        length = 0;
        if (data.Length == 0)
            return 0;
        var b0 = data[0];
        int size;
        if ((b0 & 0x80) == 0x00)
            size = 1;
        else if ((b0 & 0xC0) == 0x80)
            size = 2;
        else if ((b0 & 0xE0) == 0xC0)
            size = 3;
        else if ((b0 & 0xF0) == 0xE0)
            size = 4;
        else if (b0 == 0xF0)
            size = 5;
        else
            throw new FormatException($"Reserved RouterOS API control byte 0x{b0:X2}.");

        if (data.Length < size)
            return 0;

        long value = size switch
        {
            1 => b0,
            2 => ((b0 & 0x3F) << 8) | data[1],
            3 => ((b0 & 0x1F) << 16) | (data[1] << 8) | data[2],
            4 => ((long)(b0 & 0x0F) << 24) | ((long)data[1] << 16) | ((long)data[2] << 8) | data[3],
            _ => ((long)data[1] << 24) | ((long)data[2] << 16) | ((long)data[3] << 8) | data[4],
        };
        if (value > MaxWordLength)
            throw new FormatException($"RouterOS API word of {value} bytes exceeds the {MaxWordLength} byte limit.");
        length = (int)value;
        return size;
    }

    public static byte[] EncodeSentence(IEnumerable<string> words)
    {
        using var buffer = new MemoryStream();
        foreach (var word in words)
        {
            var bytes = Encoding.GetBytes(word);
            buffer.Write(EncodeLength(bytes.Length));
            buffer.Write(bytes);
        }
        buffer.WriteByte(0);
        return buffer.ToArray();
    }

    public static async Task WriteSentenceAsync(Stream stream, IEnumerable<string> words, CancellationToken cancellationToken)
    {
        var bytes = EncodeSentence(words);
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads one sentence. Throws <see cref="EndOfStreamException"/> when the peer closed the connection.</summary>
    public static async Task<List<string>> ReadSentenceAsync(Stream stream, CancellationToken cancellationToken)
    {
        var words = new List<string>();
        var prefix = new byte[5];
        while (true)
        {
            await stream.ReadExactlyAsync(prefix.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
            var needed = PrefixSize(prefix[0]);
            if (needed > 1)
                await stream.ReadExactlyAsync(prefix.AsMemory(1, needed - 1), cancellationToken).ConfigureAwait(false);
            DecodeLength(prefix.AsSpan(0, needed), out var length);
            if (length == 0)
                return words;

            var word = new byte[length];
            await stream.ReadExactlyAsync(word, cancellationToken).ConfigureAwait(false);
            words.Add(Encoding.GetString(word));
        }
    }

    private static int PrefixSize(byte b0)
    {
        if ((b0 & 0x80) == 0x00)
            return 1;
        if ((b0 & 0xC0) == 0x80)
            return 2;
        if ((b0 & 0xE0) == 0xC0)
            return 3;
        if ((b0 & 0xF0) == 0xE0)
            return 4;
        if (b0 == 0xF0)
            return 5;
        throw new FormatException($"Reserved RouterOS API control byte 0x{b0:X2}.");
    }
}
