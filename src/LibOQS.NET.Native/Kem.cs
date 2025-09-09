using System.Runtime.InteropServices;

namespace LibOQS.NET.Native;

/// <summary>
/// Key Encapsulation Mechanism (KEM) native bindings
/// </summary>
public static class Kem
{
    /// <summary>
    /// OQS KEM structure
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct OqsKem
    {
        public IntPtr method_name;
        public IntPtr alg_version;
        public byte claimed_nist_level;
        public byte ind_cca;
        public UIntPtr length_public_key;
        public UIntPtr length_secret_key;
        public UIntPtr length_ciphertext;
        public UIntPtr length_shared_secret;
        public IntPtr keypair_function;
        public IntPtr encaps_function;
        public IntPtr decaps_function;
    }

    /// <summary>
    /// Get a KEM by name
    /// </summary>
    [DllImport(Common.LibraryName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern IntPtr OQS_KEM_new([MarshalAs(UnmanagedType.LPStr)] string method_name);

    /// <summary>
    /// Free a KEM
    /// </summary>
    [DllImport(Common.LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void OQS_KEM_free(IntPtr kem);

    /// <summary>
    /// Generate a keypair
    /// </summary>
    [DllImport(Common.LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern Common.OqsStatus OQS_KEM_keypair(IntPtr kem, IntPtr public_key, IntPtr secret_key);

    /// <summary>
    /// Encapsulate
    /// </summary>
    [DllImport(Common.LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern Common.OqsStatus OQS_KEM_encaps(IntPtr kem, IntPtr ciphertext, IntPtr shared_secret, IntPtr public_key);

    /// <summary>
    /// Decapsulate
    /// </summary>
    [DllImport(Common.LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern Common.OqsStatus OQS_KEM_decaps(IntPtr kem, IntPtr shared_secret, IntPtr ciphertext, IntPtr secret_key);

    /// <summary>
    /// Check if a KEM algorithm is enabled
    /// </summary>
    [DllImport(Common.LibraryName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern int OQS_KEM_alg_is_enabled([MarshalAs(UnmanagedType.LPStr)] string method_name);

    /// <summary>
    /// Get the number of supported algorithms
    /// </summary>
    [DllImport(Common.LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int OQS_KEM_alg_count();

    /// <summary>
    /// Get algorithm identifier by index
    /// </summary>
    [DllImport(Common.LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr OQS_KEM_alg_identifier(int alg_index);

    // Algorithm identifiers - these would typically be const char* from the C library
    public static readonly string OQS_KEM_alg_ml_kem_512 = "ML-KEM-512";
    public static readonly string OQS_KEM_alg_ml_kem_768 = "ML-KEM-768";
    public static readonly string OQS_KEM_alg_ml_kem_1024 = "ML-KEM-1024";
    public static readonly string OQS_KEM_alg_kyber_512 = "Kyber512";
    public static readonly string OQS_KEM_alg_kyber_768 = "Kyber768";
    public static readonly string OQS_KEM_alg_kyber_1024 = "Kyber1024";
    public static readonly string OQS_KEM_alg_frodokem_640_aes = "FrodoKEM-640-AES";
    public static readonly string OQS_KEM_alg_frodokem_640_shake = "FrodoKEM-640-SHAKE";
    public static readonly string OQS_KEM_alg_frodokem_976_aes = "FrodoKEM-976-AES";
    public static readonly string OQS_KEM_alg_frodokem_976_shake = "FrodoKEM-976-SHAKE";
    public static readonly string OQS_KEM_alg_frodokem_1344_aes = "FrodoKEM-1344-AES";
    public static readonly string OQS_KEM_alg_frodokem_1344_shake = "FrodoKEM-1344-SHAKE";
}
