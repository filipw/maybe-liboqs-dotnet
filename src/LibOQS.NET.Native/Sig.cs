using System.Runtime.InteropServices;

namespace LibOQS.NET.Native;

/// <summary>
/// Digital Signature native bindings
/// </summary>
public static class Sig
{
    /// <summary>
    /// OQS Signature structure
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct OqsSig
    {
        public IntPtr method_name;
        public IntPtr alg_version;
        public byte claimed_nist_level;
        public byte euf_cma;
        public UIntPtr length_public_key;
        public UIntPtr length_secret_key;
        public UIntPtr length_signature;
        public IntPtr keypair_function;
        public IntPtr sign_function;
        public IntPtr verify_function;
    }

    /// <summary>
    /// Get a signature algorithm by name
    /// </summary>
    [DllImport(Common.LibraryName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern IntPtr OQS_SIG_new([MarshalAs(UnmanagedType.LPStr)] string method_name);

    /// <summary>
    /// Free a signature algorithm
    /// </summary>
    [DllImport(Common.LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void OQS_SIG_free(IntPtr sig);

    /// <summary>
    /// Generate a keypair
    /// </summary>
    [DllImport(Common.LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern Common.OqsStatus OQS_SIG_keypair(IntPtr sig, IntPtr public_key, IntPtr secret_key);

    /// <summary>
    /// Sign a message
    /// </summary>
    [DllImport(Common.LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern Common.OqsStatus OQS_SIG_sign(IntPtr sig, IntPtr signature, ref UIntPtr signature_len, 
        IntPtr message, UIntPtr message_len, IntPtr secret_key);

    /// <summary>
    /// Verify a signature
    /// </summary>
    [DllImport(Common.LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern Common.OqsStatus OQS_SIG_verify(IntPtr sig, IntPtr message, UIntPtr message_len, 
        IntPtr signature, UIntPtr signature_len, IntPtr public_key);

    /// <summary>
    /// Check if a signature algorithm is enabled
    /// </summary>
    [DllImport(Common.LibraryName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern int OQS_SIG_alg_is_enabled([MarshalAs(UnmanagedType.LPStr)] string method_name);

    /// <summary>
    /// Get the number of supported algorithms
    /// </summary>
    [DllImport(Common.LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int OQS_SIG_alg_count();

    /// <summary>
    /// Get algorithm identifier by index
    /// </summary>
    [DllImport(Common.LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr OQS_SIG_alg_identifier(int alg_index);

    // Algorithm identifiers - these would typically be const char* from the C library
    public static readonly string OQS_SIG_alg_ml_dsa_44 = "ML-DSA-44";
    public static readonly string OQS_SIG_alg_ml_dsa_65 = "ML-DSA-65";
    public static readonly string OQS_SIG_alg_ml_dsa_87 = "ML-DSA-87";
    public static readonly string OQS_SIG_alg_dilithium2 = "Dilithium2";
    public static readonly string OQS_SIG_alg_dilithium3 = "Dilithium3";
    public static readonly string OQS_SIG_alg_dilithium5 = "Dilithium5";
    public static readonly string OQS_SIG_alg_falcon_512 = "Falcon-512";
    public static readonly string OQS_SIG_alg_falcon_1024 = "Falcon-1024";
    public static readonly string OQS_SIG_alg_sphincs_haraka_128f_robust = "SPHINCS+-Haraka-128f-robust";
    public static readonly string OQS_SIG_alg_sphincs_haraka_128f_simple = "SPHINCS+-Haraka-128f-simple";
    public static readonly string OQS_SIG_alg_sphincs_haraka_128s_robust = "SPHINCS+-Haraka-128s-robust";
    public static readonly string OQS_SIG_alg_sphincs_haraka_128s_simple = "SPHINCS+-Haraka-128s-simple";
}
