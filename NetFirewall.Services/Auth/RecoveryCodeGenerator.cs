using System.Security.Cryptography;

namespace NetFirewall.Services.Auth;

public sealed class RecoveryCodeGenerator : IRecoveryCodeGenerator
{
    // Crockford base32 alphabet — drops 0/O/1/I/L/U so spoken/transcribed codes
    // are unambiguous. 32 symbols → 5 bits each.
    private const string Alphabet = "23456789ABCDEFGHJKMNPQRSTVWXYZ";
    private const int GroupSize = 5;       // 5 chars × 5 bits = 25 bits per group
    private const int Groups = 2;          // 50 bits total (~10^15 search space)

    public IReadOnlyList<string> Generate(int count = 10)
    {
        if (count is < 1 or > 50) throw new ArgumentOutOfRangeException(nameof(count));

        var codes = new string[count];
        Span<char> buffer = stackalloc char[GroupSize * Groups + (Groups - 1)];

        for (var i = 0; i < count; i++)
            codes[i] = GenerateOne(buffer);

        return codes;
    }

    private static string GenerateOne(Span<char> buffer)
    {
        var pos = 0;
        for (var g = 0; g < Groups; g++)
        {
            if (g > 0) buffer[pos++] = '-';
            for (var c = 0; c < GroupSize; c++)
            {
                // RandomNumberGenerator.GetInt32 is unbiased.
                buffer[pos++] = Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)];
            }
        }
        return new string(buffer);
    }
}
