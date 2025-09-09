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
    /// <summary>SPHINCS+-Haraka-128f-robust</summary>
    SphincsPlusHaraka128fRobust,
    /// <summary>SPHINCS+-Haraka-128f-simple</summary>
    SphincsPlusHaraka128fSimple,
    /// <summary>SPHINCS+-Haraka-128s-robust</summary>
    SphincsPlusHaraka128sRobust,
    /// <summary>SPHINCS+-Haraka-128s-simple</summary>
    SphincsPlusHaraka128sSimple,
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
        SigAlgorithm.SphincsPlusHaraka128fRobust => Sig.OQS_SIG_alg_sphincs_haraka_128f_robust,
        SigAlgorithm.SphincsPlusHaraka128fSimple => Sig.OQS_SIG_alg_sphincs_haraka_128f_simple,
        SigAlgorithm.SphincsPlusHaraka128sRobust => Sig.OQS_SIG_alg_sphincs_haraka_128s_robust,
        SigAlgorithm.SphincsPlusHaraka128sSimple => Sig.OQS_SIG_alg_sphincs_haraka_128s_simple,
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
