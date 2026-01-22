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
        public byte suf_cma;
        public byte sig_with_ctx_support;
        public UIntPtr length_public_key;
        public UIntPtr length_secret_key;
        public UIntPtr length_signature;
        public IntPtr keypair_function;
        public IntPtr sign_function;
        public IntPtr sign_with_ctx_str_function;
        public IntPtr verify_function;
        public IntPtr verify_with_ctx_str_function;
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
    /// Sign a message with a context string
    /// </summary>
    [DllImport(Common.LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern Common.OqsStatus OQS_SIG_sign_with_ctx_str(IntPtr sig, IntPtr signature, ref UIntPtr signature_len,
        IntPtr message, UIntPtr message_len, IntPtr ctx_str, UIntPtr ctx_str_len, IntPtr secret_key);

    /// <summary>
    /// Verify a signature
    /// </summary>
    [DllImport(Common.LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern Common.OqsStatus OQS_SIG_verify(IntPtr sig, IntPtr message, UIntPtr message_len,
        IntPtr signature, UIntPtr signature_len, IntPtr public_key);

    /// <summary>
    /// Verify a signature with a context string
    /// </summary>
    [DllImport(Common.LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern Common.OqsStatus OQS_SIG_verify_with_ctx_str(IntPtr sig, IntPtr message, UIntPtr message_len,
        IntPtr signature, UIntPtr signature_len, IntPtr ctx_str, UIntPtr ctx_str_len, IntPtr public_key);

    /// <summary>
    /// Check if a signature algorithm supports context strings
    /// </summary>
    [DllImport(Common.LibraryName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern bool OQS_SIG_supports_ctx_str([MarshalAs(UnmanagedType.LPStr)] string method_name);

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
    public static readonly string OQS_SIG_alg_falcon_512 = "Falcon-512";
    public static readonly string OQS_SIG_alg_falcon_1024 = "Falcon-1024";
    public static readonly string OQS_SIG_alg_falcon_padded_512 = "Falcon-padded-512";
    public static readonly string OQS_SIG_alg_falcon_padded_1024 = "Falcon-padded-1024";
    public static readonly string OQS_SIG_alg_sphincs_sha2_128f_simple = "SPHINCS+-SHA2-128f-simple";
    public static readonly string OQS_SIG_alg_sphincs_sha2_128s_simple = "SPHINCS+-SHA2-128s-simple";
    public static readonly string OQS_SIG_alg_sphincs_sha2_192f_simple = "SPHINCS+-SHA2-192f-simple";
    public static readonly string OQS_SIG_alg_sphincs_sha2_192s_simple = "SPHINCS+-SHA2-192s-simple";
    public static readonly string OQS_SIG_alg_sphincs_sha2_256f_simple = "SPHINCS+-SHA2-256f-simple";
    public static readonly string OQS_SIG_alg_sphincs_sha2_256s_simple = "SPHINCS+-SHA2-256s-simple";
    public static readonly string OQS_SIG_alg_sphincs_shake_128f_simple = "SPHINCS+-SHAKE-128f-simple";
    public static readonly string OQS_SIG_alg_sphincs_shake_128s_simple = "SPHINCS+-SHAKE-128s-simple";
    public static readonly string OQS_SIG_alg_sphincs_shake_192f_simple = "SPHINCS+-SHAKE-192f-simple";
    public static readonly string OQS_SIG_alg_sphincs_shake_192s_simple = "SPHINCS+-SHAKE-192s-simple";
    public static readonly string OQS_SIG_alg_sphincs_shake_256f_simple = "SPHINCS+-SHAKE-256f-simple";
    public static readonly string OQS_SIG_alg_sphincs_shake_256s_simple = "SPHINCS+-SHAKE-256s-simple";
    public static readonly string OQS_SIG_alg_mayo_1 = "MAYO-1";
    public static readonly string OQS_SIG_alg_mayo_2 = "MAYO-2";
    public static readonly string OQS_SIG_alg_mayo_3 = "MAYO-3";
    public static readonly string OQS_SIG_alg_mayo_5 = "MAYO-5";
    public static readonly string OQS_SIG_alg_cross_rsdp_128_balanced = "cross-rsdp-128-balanced";
    public static readonly string OQS_SIG_alg_cross_rsdp_128_fast = "cross-rsdp-128-fast";
    public static readonly string OQS_SIG_alg_cross_rsdp_128_small = "cross-rsdp-128-small";
    public static readonly string OQS_SIG_alg_cross_rsdp_192_balanced = "cross-rsdp-192-balanced";
    public static readonly string OQS_SIG_alg_cross_rsdp_192_fast = "cross-rsdp-192-fast";
    public static readonly string OQS_SIG_alg_cross_rsdp_192_small = "cross-rsdp-192-small";
    public static readonly string OQS_SIG_alg_cross_rsdp_256_balanced = "cross-rsdp-256-balanced";
    public static readonly string OQS_SIG_alg_cross_rsdp_256_fast = "cross-rsdp-256-fast";
    public static readonly string OQS_SIG_alg_cross_rsdp_256_small = "cross-rsdp-256-small";
    public static readonly string OQS_SIG_alg_cross_rsdpg_128_balanced = "cross-rsdpg-128-balanced";
    public static readonly string OQS_SIG_alg_cross_rsdpg_128_fast = "cross-rsdpg-128-fast";
    public static readonly string OQS_SIG_alg_cross_rsdpg_128_small = "cross-rsdpg-128-small";
    public static readonly string OQS_SIG_alg_cross_rsdpg_192_balanced = "cross-rsdpg-192-balanced";
    public static readonly string OQS_SIG_alg_cross_rsdpg_192_fast = "cross-rsdpg-192-fast";
    public static readonly string OQS_SIG_alg_cross_rsdpg_192_small = "cross-rsdpg-192-small";
    public static readonly string OQS_SIG_alg_cross_rsdpg_256_balanced = "cross-rsdpg-256-balanced";
    public static readonly string OQS_SIG_alg_cross_rsdpg_256_fast = "cross-rsdpg-256-fast";
    public static readonly string OQS_SIG_alg_cross_rsdpg_256_small = "cross-rsdpg-256-small";
    public static readonly string OQS_SIG_alg_uov_ov_Is = "OV-Is";
    public static readonly string OQS_SIG_alg_uov_ov_Ip = "OV-Ip";
    public static readonly string OQS_SIG_alg_uov_ov_III = "OV-III";
    public static readonly string OQS_SIG_alg_uov_ov_V = "OV-V";
    public static readonly string OQS_SIG_alg_uov_ov_Is_pkc = "OV-Is-pkc";
    public static readonly string OQS_SIG_alg_uov_ov_Ip_pkc = "OV-Ip-pkc";
    public static readonly string OQS_SIG_alg_uov_ov_III_pkc = "OV-III-pkc";
    public static readonly string OQS_SIG_alg_uov_ov_V_pkc = "OV-V-pkc";
    public static readonly string OQS_SIG_alg_uov_ov_Is_pkc_skc = "OV-Is-pkc-skc";
    public static readonly string OQS_SIG_alg_uov_ov_Ip_pkc_skc = "OV-Ip-pkc-skc";
    public static readonly string OQS_SIG_alg_uov_ov_III_pkc_skc = "OV-III-pkc-skc";
    public static readonly string OQS_SIG_alg_uov_ov_V_pkc_skc = "OV-V-pkc-skc";

    // SLH-DSA identifiers
    public static readonly string OQS_SIG_alg_slh_dsa_sha2_128s_pure = "SLH_DSA_PURE_SHA2_128S";
    public static readonly string OQS_SIG_alg_slh_dsa_sha2_128f_pure = "SLH_DSA_PURE_SHA2_128F";
    public static readonly string OQS_SIG_alg_slh_dsa_sha2_192s_pure = "SLH_DSA_PURE_SHA2_192S";
    public static readonly string OQS_SIG_alg_slh_dsa_sha2_192f_pure = "SLH_DSA_PURE_SHA2_192F";
    public static readonly string OQS_SIG_alg_slh_dsa_sha2_256s_pure = "SLH_DSA_PURE_SHA2_256S";
    public static readonly string OQS_SIG_alg_slh_dsa_sha2_256f_pure = "SLH_DSA_PURE_SHA2_256F";
    public static readonly string OQS_SIG_alg_slh_dsa_shake_128s_pure = "SLH_DSA_PURE_SHAKE_128S";
    public static readonly string OQS_SIG_alg_slh_dsa_shake_128f_pure = "SLH_DSA_PURE_SHAKE_128F";
    public static readonly string OQS_SIG_alg_slh_dsa_shake_192s_pure = "SLH_DSA_PURE_SHAKE_192S";
    public static readonly string OQS_SIG_alg_slh_dsa_shake_192f_pure = "SLH_DSA_PURE_SHAKE_192F";
    public static readonly string OQS_SIG_alg_slh_dsa_shake_256s_pure = "SLH_DSA_PURE_SHAKE_256S";
    public static readonly string OQS_SIG_alg_slh_dsa_shake_256f_pure = "SLH_DSA_PURE_SHAKE_256F";

    // SNOVA identifiers
    public static readonly string OQS_SIG_alg_snova_24_5_4 = "SNOVA_24_5_4";
    public static readonly string OQS_SIG_alg_snova_24_5_4_shake = "SNOVA_24_5_4_SHAKE";
    public static readonly string OQS_SIG_alg_snova_24_5_4_esk = "SNOVA_24_5_4_esk";
    public static readonly string OQS_SIG_alg_snova_24_5_4_shake_esk = "SNOVA_24_5_4_SHAKE_esk";
    public static readonly string OQS_SIG_alg_snova_37_17_2 = "SNOVA_37_17_2";
    public static readonly string OQS_SIG_alg_snova_25_8_3 = "SNOVA_25_8_3";
    public static readonly string OQS_SIG_alg_snova_56_25_2 = "SNOVA_56_25_2";
    public static readonly string OQS_SIG_alg_snova_49_11_3 = "SNOVA_49_11_3";
    public static readonly string OQS_SIG_alg_snova_37_8_4 = "SNOVA_37_8_4";
    public static readonly string OQS_SIG_alg_snova_24_5_5 = "SNOVA_24_5_5";
    public static readonly string OQS_SIG_alg_snova_60_10_4 = "SNOVA_60_10_4";
    public static readonly string OQS_SIG_alg_snova_29_6_5 = "SNOVA_29_6_5";
}
