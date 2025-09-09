using System.Runtime.InteropServices;
using LibOQS.NET.Native;

namespace LibOQS.NET;

/// <summary>
/// Key Encapsulation Mechanism (KEM) algorithms
/// </summary>
public enum KemAlgorithm
{
    /// <summary>ML-KEM-512 (NIST standardized)</summary>
    MlKem512,
    /// <summary>ML-KEM-768 (NIST standardized)</summary>
    MlKem768,
    /// <summary>ML-KEM-1024 (NIST standardized)</summary>
    MlKem1024,
    /// <summary>Kyber512</summary>
    Kyber512,
    /// <summary>Kyber768</summary>
    Kyber768,
    /// <summary>Kyber1024</summary>
    Kyber1024,
    /// <summary>FrodoKEM-640-AES</summary>
    FrodoKem640Aes,
    /// <summary>FrodoKEM-640-SHAKE</summary>
    FrodoKem640Shake,
    /// <summary>FrodoKEM-976-AES</summary>
    FrodoKem976Aes,
    /// <summary>FrodoKEM-976-SHAKE</summary>
    FrodoKem976Shake,
    /// <summary>FrodoKEM-1344-AES</summary>
    FrodoKem1344Aes,
    /// <summary>FrodoKEM-1344-SHAKE</summary>
    FrodoKem1344Shake,
}

/// <summary>
/// Extension methods for KEM algorithms
/// </summary>
public static class KemAlgorithmExtensions
{
    /// <summary>
    /// Get the string identifier for the algorithm
    /// </summary>
    public static string GetIdentifier(this KemAlgorithm algorithm) => algorithm switch
    {
        KemAlgorithm.MlKem512 => Kem.OQS_KEM_alg_ml_kem_512,
        KemAlgorithm.MlKem768 => Kem.OQS_KEM_alg_ml_kem_768,
        KemAlgorithm.MlKem1024 => Kem.OQS_KEM_alg_ml_kem_1024,
        KemAlgorithm.Kyber512 => Kem.OQS_KEM_alg_kyber_512,
        KemAlgorithm.Kyber768 => Kem.OQS_KEM_alg_kyber_768,
        KemAlgorithm.Kyber1024 => Kem.OQS_KEM_alg_kyber_1024,
        KemAlgorithm.FrodoKem640Aes => Kem.OQS_KEM_alg_frodokem_640_aes,
        KemAlgorithm.FrodoKem640Shake => Kem.OQS_KEM_alg_frodokem_640_shake,
        KemAlgorithm.FrodoKem976Aes => Kem.OQS_KEM_alg_frodokem_976_aes,
        KemAlgorithm.FrodoKem976Shake => Kem.OQS_KEM_alg_frodokem_976_shake,
        KemAlgorithm.FrodoKem1344Aes => Kem.OQS_KEM_alg_frodokem_1344_aes,
        KemAlgorithm.FrodoKem1344Shake => Kem.OQS_KEM_alg_frodokem_1344_shake,
        _ => throw new ArgumentException($"Unknown algorithm: {algorithm}")
    };

    /// <summary>
    /// Check if the algorithm is enabled in the current build
    /// </summary>
    public static bool IsEnabled(this KemAlgorithm algorithm)
    {
        LibOqs.EnsureInitialized();
        return Kem.OQS_KEM_alg_is_enabled(algorithm.GetIdentifier()) != 0;
    }
}

/// <summary>
/// Key Encapsulation Mechanism wrapper
/// </summary>
public class KemInstance : IDisposable
{
    private IntPtr _kemPtr;
    private Kem.OqsKem _kem;
    private bool _disposed = false;

    /// <summary>
    /// Algorithm being used
    /// </summary>
    public KemAlgorithm Algorithm { get; }

    /// <summary>
    /// Length of public keys in bytes
    /// </summary>
    public int PublicKeyLength => (int)_kem.length_public_key;

    /// <summary>
    /// Length of secret keys in bytes
    /// </summary>
    public int SecretKeyLength => (int)_kem.length_secret_key;

    /// <summary>
    /// Length of ciphertexts in bytes
    /// </summary>
    public int CiphertextLength => (int)_kem.length_ciphertext;

    /// <summary>
    /// Length of shared secrets in bytes
    /// </summary>
    public int SharedSecretLength => (int)_kem.length_shared_secret;

    /// <summary>
    /// Create a new KEM instance
    /// </summary>
    public KemInstance(KemAlgorithm algorithm)
    {
        LibOqs.EnsureInitialized();
        Algorithm = algorithm;
        
        if (!algorithm.IsEnabled())
        {
            throw new AlgorithmNotSupportedException(algorithm.GetIdentifier());
        }

        _kemPtr = Kem.OQS_KEM_new(algorithm.GetIdentifier());
        if (_kemPtr == IntPtr.Zero)
        {
            throw new OqsException($"Failed to create KEM instance for {algorithm}");
        }

        _kem = Marshal.PtrToStructure<Kem.OqsKem>(_kemPtr);
    }

    /// <summary>
    /// Helper method to check if the instance has been disposed
    /// </summary>
    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(KemInstance));
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
                var result = Kem.OQS_KEM_keypair(_kemPtr, (IntPtr)pkPtr, (IntPtr)skPtr);
                if (result != Common.OqsStatus.Success)
                {
                    throw new OqsException("Failed to generate keypair");
                }
            }
        }

        return (publicKey, secretKey);
    }

    /// <summary>
    /// Encapsulate a shared secret using the public key
    /// </summary>
    public (byte[] Ciphertext, byte[] SharedSecret) Encapsulate(byte[] publicKey)
    {
        ThrowIfDisposed();
        
        if (publicKey.Length != PublicKeyLength)
        {
            throw new ArgumentException($"Public key must be {PublicKeyLength} bytes");
        }

        var ciphertext = new byte[CiphertextLength];
        var sharedSecret = new byte[SharedSecretLength];

        unsafe
        {
            fixed (byte* pkPtr = publicKey, ctPtr = ciphertext, ssPtr = sharedSecret)
            {
                var result = Kem.OQS_KEM_encaps(_kemPtr, (IntPtr)ctPtr, (IntPtr)ssPtr, (IntPtr)pkPtr);
                if (result != Common.OqsStatus.Success)
                {
                    throw new OqsException("Failed to encapsulate");
                }
            }
        }

        return (ciphertext, sharedSecret);
    }

    /// <summary>
    /// Decapsulate a shared secret using the secret key
    /// </summary>
    public byte[] Decapsulate(byte[] secretKey, byte[] ciphertext)
    {
        ThrowIfDisposed();
        
        if (secretKey.Length != SecretKeyLength)
        {
            throw new ArgumentException($"Secret key must be {SecretKeyLength} bytes");
        }
        
        if (ciphertext.Length != CiphertextLength)
        {
            throw new ArgumentException($"Ciphertext must be {CiphertextLength} bytes");
        }

        var sharedSecret = new byte[SharedSecretLength];

        unsafe
        {
            fixed (byte* skPtr = secretKey, ctPtr = ciphertext, ssPtr = sharedSecret)
            {
                var result = Kem.OQS_KEM_decaps(_kemPtr, (IntPtr)ssPtr, (IntPtr)ctPtr, (IntPtr)skPtr);
                if (result != Common.OqsStatus.Success)
                {
                    throw new OqsException("Failed to decapsulate");
                }
            }
        }

        return sharedSecret;
    }

    /// <summary>
    /// Dispose of the KEM instance
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            if (_kemPtr != IntPtr.Zero)
            {
                Kem.OQS_KEM_free(_kemPtr);
                _kemPtr = IntPtr.Zero;
            }
            _disposed = true;
        }
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Finalizer
    /// </summary>
    ~KemInstance()
    {
        Dispose();
    }
}
