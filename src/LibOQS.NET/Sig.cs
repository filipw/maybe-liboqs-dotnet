using System.Runtime.InteropServices;
using LibOQS.NET.Native;

namespace LibOQS.NET;

/// <summary>
/// Digital Signature algorithms
/// </summary>
public enum SigAlgorithm
{
    /// <summary>ML-DSA-44 (NIST standardized)</summary>
    MlDsa44,
    /// <summary>ML-DSA-65 (NIST standardized)</summary>
    MlDsa65,
    /// <summary>ML-DSA-87 (NIST standardized)</summary>
    MlDsa87,
    /// <summary>Dilithium2</summary>
    Dilithium2,
    /// <summary>Dilithium3</summary>
    Dilithium3,
    /// <summary>Dilithium5</summary>
    Dilithium5,
    /// <summary>Falcon-512</summary>
    Falcon512,
    /// <summary>Falcon-1024</summary>
    Falcon1024,
    /// <summary>Falcon-padded-512</summary>
    FalconPadded512,
    /// <summary>Falcon-padded-1024</summary>
    FalconPadded1024,
    /// <summary>SPHINCS+-SHA2-128f-simple</summary>
    SphincsPlusSha2128fSimple,
    /// <summary>SPHINCS+-SHA2-128s-simple</summary>
    SphincsPlusSha2128sSimple,
    /// <summary>SPHINCS+-SHA2-192f-simple</summary>
    SphincsPlusSha2192fSimple,
    /// <summary>SPHINCS+-SHA2-192s-simple</summary>
    SphincsPlusSha2192sSimple,
    /// <summary>SPHINCS+-SHA2-256f-simple</summary>
    SphincsPlusSha2256fSimple,
    /// <summary>SPHINCS+-SHA2-256s-simple</summary>
    SphincsPlusSha2256sSimple,
    /// <summary>SPHINCS+-SHAKE-128f-simple</summary>
    SphincsPlusShake128fSimple,
    /// <summary>SPHINCS+-SHAKE-128s-simple</summary>
    SphincsPlusShake128sSimple,
    /// <summary>SPHINCS+-SHAKE-192f-simple</summary>
    SphincsPlusShake192fSimple,
    /// <summary>SPHINCS+-SHAKE-192s-simple</summary>
    SphincsPlusShake192sSimple,
    /// <summary>SPHINCS+-SHAKE-256f-simple</summary>
    SphincsPlusShake256fSimple,
    /// <summary>SPHINCS+-SHAKE-256s-simple</summary>
    SphincsPlusShake256sSimple,
    /// <summary>MAYO-1</summary>
    Mayo1,
    /// <summary>MAYO-2</summary>
    Mayo2,
    /// <summary>MAYO-3</summary>
    Mayo3,
    /// <summary>MAYO-5</summary>
    Mayo5,
    /// <summary>cross-rsdp-128-balanced</summary>
    CrossRsdp128Balanced,
    /// <summary>cross-rsdp-128-fast</summary>
    CrossRsdp128Fast,
    /// <summary>cross-rsdp-128-small</summary>
    CrossRsdp128Small,
    /// <summary>cross-rsdp-192-balanced</summary>
    CrossRsdp192Balanced,
    /// <summary>cross-rsdp-192-fast</summary>
    CrossRsdp192Fast,
    /// <summary>cross-rsdp-192-small</summary>
    CrossRsdp192Small,
    /// <summary>cross-rsdp-256-balanced</summary>
    CrossRsdp256Balanced,
    /// <summary>cross-rsdp-256-fast</summary>
    CrossRsdp256Fast,
    /// <summary>cross-rsdp-256-small</summary>
    CrossRsdp256Small,
    /// <summary>cross-rsdpg-128-balanced</summary>
    CrossRsdpg128Balanced,
    /// <summary>cross-rsdpg-128-fast</summary>
    CrossRsdpg128Fast,
    /// <summary>cross-rsdpg-128-small</summary>
    CrossRsdpg128Small,
    /// <summary>cross-rsdpg-192-balanced</summary>
    CrossRsdpg192Balanced,
    /// <summary>cross-rsdpg-192-fast</summary>
    CrossRsdpg192Fast,
    /// <summary>cross-rsdpg-192-small</summary>
    CrossRsdpg192Small,
    /// <summary>cross-rsdpg-256-balanced</summary>
    CrossRsdpg256Balanced,
    /// <summary>cross-rsdpg-256-fast</summary>
    CrossRsdpg256Fast,
    /// <summary>cross-rsdpg-256-small</summary>
    CrossRsdpg256Small,
    /// <summary>OV-Is</summary>
    UovOvIs,
    /// <summary>OV-Ip</summary>
    UovOvIp,
    /// <summary>OV-III</summary>
    UovOvIii,
    /// <summary>OV-V</summary>
    UovOvV,
    /// <summary>OV-Is-pkc</summary>
    UovOvIsPkc,
    /// <summary>OV-Ip-pkc</summary>
    UovOvIpPkc,
    /// <summary>OV-III-pkc</summary>
    UovOvIiiPkc,
    /// <summary>OV-V-pkc</summary>
    UovOvVPkc,
    /// <summary>OV-Is-pkc-skc</summary>
    UovOvIsPkcSkc,
    /// <summary>OV-Ip-pkc-skc</summary>
    UovOvIpPkcSkc,
    /// <summary>OV-III-pkc-skc</summary>
    UovOvIiiPkcSkc,
    /// <summary>OV-V-pkc-skc</summary>
    UovOvVPkcSkc,
}

/// <summary>
/// Extension methods for signature algorithms
/// </summary>
public static class SigAlgorithmExtensions
{
    /// <summary>
    /// Get the string identifier for the algorithm
    /// </summary>
    public static string GetIdentifier(this SigAlgorithm algorithm) => algorithm switch
    {
        SigAlgorithm.MlDsa44 => Sig.OQS_SIG_alg_ml_dsa_44,
        SigAlgorithm.MlDsa65 => Sig.OQS_SIG_alg_ml_dsa_65,
        SigAlgorithm.MlDsa87 => Sig.OQS_SIG_alg_ml_dsa_87,
        SigAlgorithm.Dilithium2 => Sig.OQS_SIG_alg_dilithium2,
        SigAlgorithm.Dilithium3 => Sig.OQS_SIG_alg_dilithium3,
        SigAlgorithm.Dilithium5 => Sig.OQS_SIG_alg_dilithium5,
        SigAlgorithm.Falcon512 => Sig.OQS_SIG_alg_falcon_512,
        SigAlgorithm.Falcon1024 => Sig.OQS_SIG_alg_falcon_1024,
        SigAlgorithm.FalconPadded512 => Sig.OQS_SIG_alg_falcon_padded_512,
        SigAlgorithm.FalconPadded1024 => Sig.OQS_SIG_alg_falcon_padded_1024,
        SigAlgorithm.SphincsPlusSha2128fSimple => Sig.OQS_SIG_alg_sphincs_sha2_128f_simple,
        SigAlgorithm.SphincsPlusSha2128sSimple => Sig.OQS_SIG_alg_sphincs_sha2_128s_simple,
        SigAlgorithm.SphincsPlusSha2192fSimple => Sig.OQS_SIG_alg_sphincs_sha2_192f_simple,
        SigAlgorithm.SphincsPlusSha2192sSimple => Sig.OQS_SIG_alg_sphincs_sha2_192s_simple,
        SigAlgorithm.SphincsPlusSha2256fSimple => Sig.OQS_SIG_alg_sphincs_sha2_256f_simple,
        SigAlgorithm.SphincsPlusSha2256sSimple => Sig.OQS_SIG_alg_sphincs_sha2_256s_simple,
        SigAlgorithm.SphincsPlusShake128fSimple => Sig.OQS_SIG_alg_sphincs_shake_128f_simple,
        SigAlgorithm.SphincsPlusShake128sSimple => Sig.OQS_SIG_alg_sphincs_shake_128s_simple,
        SigAlgorithm.SphincsPlusShake192fSimple => Sig.OQS_SIG_alg_sphincs_shake_192f_simple,
        SigAlgorithm.SphincsPlusShake192sSimple => Sig.OQS_SIG_alg_sphincs_shake_192s_simple,
        SigAlgorithm.SphincsPlusShake256fSimple => Sig.OQS_SIG_alg_sphincs_shake_256f_simple,
        SigAlgorithm.SphincsPlusShake256sSimple => Sig.OQS_SIG_alg_sphincs_shake_256s_simple,
        SigAlgorithm.Mayo1 => Sig.OQS_SIG_alg_mayo_1,
        SigAlgorithm.Mayo2 => Sig.OQS_SIG_alg_mayo_2,
        SigAlgorithm.Mayo3 => Sig.OQS_SIG_alg_mayo_3,
        SigAlgorithm.Mayo5 => Sig.OQS_SIG_alg_mayo_5,
        SigAlgorithm.CrossRsdp128Balanced => Sig.OQS_SIG_alg_cross_rsdp_128_balanced,
        SigAlgorithm.CrossRsdp128Fast => Sig.OQS_SIG_alg_cross_rsdp_128_fast,
        SigAlgorithm.CrossRsdp128Small => Sig.OQS_SIG_alg_cross_rsdp_128_small,
        SigAlgorithm.CrossRsdp192Balanced => Sig.OQS_SIG_alg_cross_rsdp_192_balanced,
        SigAlgorithm.CrossRsdp192Fast => Sig.OQS_SIG_alg_cross_rsdp_192_fast,
        SigAlgorithm.CrossRsdp192Small => Sig.OQS_SIG_alg_cross_rsdp_192_small,
        SigAlgorithm.CrossRsdp256Balanced => Sig.OQS_SIG_alg_cross_rsdp_256_balanced,
        SigAlgorithm.CrossRsdp256Fast => Sig.OQS_SIG_alg_cross_rsdp_256_fast,
        SigAlgorithm.CrossRsdp256Small => Sig.OQS_SIG_alg_cross_rsdp_256_small,
        SigAlgorithm.CrossRsdpg128Balanced => Sig.OQS_SIG_alg_cross_rsdpg_128_balanced,
        SigAlgorithm.CrossRsdpg128Fast => Sig.OQS_SIG_alg_cross_rsdpg_128_fast,
        SigAlgorithm.CrossRsdpg128Small => Sig.OQS_SIG_alg_cross_rsdpg_128_small,
        SigAlgorithm.CrossRsdpg192Balanced => Sig.OQS_SIG_alg_cross_rsdpg_192_balanced,
        SigAlgorithm.CrossRsdpg192Fast => Sig.OQS_SIG_alg_cross_rsdpg_192_fast,
        SigAlgorithm.CrossRsdpg192Small => Sig.OQS_SIG_alg_cross_rsdpg_192_small,
        SigAlgorithm.CrossRsdpg256Balanced => Sig.OQS_SIG_alg_cross_rsdpg_256_balanced,
        SigAlgorithm.CrossRsdpg256Fast => Sig.OQS_SIG_alg_cross_rsdpg_256_fast,
        SigAlgorithm.CrossRsdpg256Small => Sig.OQS_SIG_alg_cross_rsdpg_256_small,
        SigAlgorithm.UovOvIs => Sig.OQS_SIG_alg_uov_ov_Is,
        SigAlgorithm.UovOvIp => Sig.OQS_SIG_alg_uov_ov_Ip,
        SigAlgorithm.UovOvIii => Sig.OQS_SIG_alg_uov_ov_III,
        SigAlgorithm.UovOvV => Sig.OQS_SIG_alg_uov_ov_V,
        SigAlgorithm.UovOvIsPkc => Sig.OQS_SIG_alg_uov_ov_Is_pkc,
        SigAlgorithm.UovOvIpPkc => Sig.OQS_SIG_alg_uov_ov_Ip_pkc,
        SigAlgorithm.UovOvIiiPkc => Sig.OQS_SIG_alg_uov_ov_III_pkc,
        SigAlgorithm.UovOvVPkc => Sig.OQS_SIG_alg_uov_ov_V_pkc,
        SigAlgorithm.UovOvIsPkcSkc => Sig.OQS_SIG_alg_uov_ov_Is_pkc_skc,
        SigAlgorithm.UovOvIpPkcSkc => Sig.OQS_SIG_alg_uov_ov_Ip_pkc_skc,
        SigAlgorithm.UovOvIiiPkcSkc => Sig.OQS_SIG_alg_uov_ov_III_pkc_skc,
        SigAlgorithm.UovOvVPkcSkc => Sig.OQS_SIG_alg_uov_ov_V_pkc_skc,
        _ => throw new ArgumentException($"Unknown algorithm: {algorithm}")
    };

    /// <summary>
    /// Check if the algorithm is enabled in the current build
    /// </summary>
    public static bool IsEnabled(this SigAlgorithm algorithm)
    {
        LibOqs.EnsureInitialized();
        return Sig.OQS_SIG_alg_is_enabled(algorithm.GetIdentifier()) != 0;
    }
}

/// <summary>
/// Digital Signature wrapper
/// </summary>
public class SigInstance : IDisposable
{
    private IntPtr _sigPtr;
    private Sig.OqsSig _sig;
    private bool _disposed = false;

    /// <summary>
    /// Algorithm being used
    /// </summary>
    public SigAlgorithm Algorithm { get; }

    /// <summary>
    /// Length of public keys in bytes
    /// </summary>
    public int PublicKeyLength => (int)_sig.length_public_key;

    /// <summary>
    /// Length of secret keys in bytes
    /// </summary>
    public int SecretKeyLength => (int)_sig.length_secret_key;

    /// <summary>
    /// Maximum length of signatures in bytes
    /// </summary>
    public int MaxSignatureLength => (int)_sig.length_signature;

    /// <summary>
    /// Create a new signature instance
    /// </summary>
    public SigInstance(SigAlgorithm algorithm)
    {
        LibOqs.EnsureInitialized();
        Algorithm = algorithm;

        if (!algorithm.IsEnabled())
        {
            throw new AlgorithmNotSupportedException(algorithm.GetIdentifier());
        }

        _sigPtr = Sig.OQS_SIG_new(algorithm.GetIdentifier());
        if (_sigPtr == IntPtr.Zero)
        {
            throw new OqsException($"Failed to create signature instance for {algorithm}");
        }

        _sig = Marshal.PtrToStructure<Sig.OqsSig>(_sigPtr);
    }

    /// <summary>
    /// Helper method to check if the instance has been disposed
    /// </summary>
    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(SigInstance));
        }
    }

    /// <summary>
    /// Generate a new keypair
    /// </summary>
    public (byte[] PublicKey, byte[] SecretKey) GenerateKeypair()
    {
        ThrowIfDisposed();

        var publicKey = new byte[PublicKeyLength];
        var secretKey = new byte[SecretKeyLength];

        unsafe
        {
            fixed (byte* pkPtr = publicKey, skPtr = secretKey)
            {
                var result = Sig.OQS_SIG_keypair(_sigPtr, (IntPtr)pkPtr, (IntPtr)skPtr);
                if (result != Common.OqsStatus.Success)
                {
                    throw new OqsException("Failed to generate keypair");
                }
            }
        }

        return (publicKey, secretKey);
    }

    /// <summary>
    /// Sign a message
    /// </summary>
    public byte[] Sign(byte[] message, byte[] secretKey)
    {
        ThrowIfDisposed();

        if (secretKey.Length != SecretKeyLength)
        {
            throw new ArgumentException($"Secret key must be {SecretKeyLength} bytes");
        }

        var signature = new byte[MaxSignatureLength];
        var signatureLength = (UIntPtr)MaxSignatureLength;

        unsafe
        {
            fixed (byte* msgPtr = message, skPtr = secretKey, sigPtr = signature)
            {
                var result = Sig.OQS_SIG_sign(_sigPtr, (IntPtr)sigPtr, ref signatureLength,
                    (IntPtr)msgPtr, (UIntPtr)message.Length, (IntPtr)skPtr);
                if (result != Common.OqsStatus.Success)
                {
                    throw new OqsException("Failed to sign message");
                }
            }
        }

        // Return only the actual signature length
        var actualSignature = new byte[(int)signatureLength];
        Array.Copy(signature, actualSignature, (int)signatureLength);
        return actualSignature;
    }

    /// <summary>
    /// Verify a signature
    /// </summary>
    public bool Verify(byte[] message, byte[] signature, byte[] publicKey)
    {
        ThrowIfDisposed();

        if (publicKey.Length != PublicKeyLength)
        {
            throw new ArgumentException($"Public key must be {PublicKeyLength} bytes");
        }

        unsafe
        {
            fixed (byte* msgPtr = message, sigPtr = signature, pkPtr = publicKey)
            {
                var result = Sig.OQS_SIG_verify(_sigPtr, (IntPtr)msgPtr, (UIntPtr)message.Length,
                    (IntPtr)sigPtr, (UIntPtr)signature.Length, (IntPtr)pkPtr);
                return result == Common.OqsStatus.Success;
            }
        }
    }

    /// <summary>
    /// Dispose of the signature instance
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            if (_sigPtr != IntPtr.Zero)
            {
                Sig.OQS_SIG_free(_sigPtr);
                _sigPtr = IntPtr.Zero;
            }
            _disposed = true;
        }
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Finalizer
    /// </summary>
    ~SigInstance()
    {
        Dispose();
    }
}
