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
    /// <summary>BIKE-L1</summary>
    BikeL1,
    /// <summary>BIKE-L3</summary>
    BikeL3,
    /// <summary>BIKE-L5</summary>
    BikeL5,
    /// <summary>HQC-1</summary>
    Hqc1,
    /// <summary>HQC-3</summary>
    Hqc3,
    /// <summary>HQC-5</summary>
    Hqc5,
    /// <summary>NTRU-HPS-2048-509</summary>
    NtruHps2048509,
    /// <summary>NTRU-HPS-2048-677</summary>
    NtruHps2048677,
    /// <summary>NTRU-HPS-4096-821</summary>
    NtruHps4096821,
    /// <summary>NTRU-HPS-4096-1229</summary>
    NtruHps40961229,
    /// <summary>NTRU-HRSS-701</summary>
    NtruHrss701,
    /// <summary>NTRU-HRSS-1373</summary>
    NtruHrss1373,
    /// <summary>sntrup761 (NTRU Prime)</summary>
    NtruPrimeSntrup761,
    /// <summary>Classic-McEliece-348864</summary>
    ClassicMcEliece348864,
    /// <summary>Classic-McEliece-348864f</summary>
    ClassicMcEliece348864f,
    /// <summary>Classic-McEliece-460896</summary>
    ClassicMcEliece460896,
    /// <summary>Classic-McEliece-460896f</summary>
    ClassicMcEliece460896f,
    /// <summary>Classic-McEliece-6688128</summary>
    ClassicMcEliece6688128,
    /// <summary>Classic-McEliece-6688128f</summary>
    ClassicMcEliece6688128f,
    /// <summary>Classic-McEliece-6960119</summary>
    ClassicMcEliece6960119,
    /// <summary>Classic-McEliece-6960119f</summary>
    ClassicMcEliece6960119f,
    /// <summary>Classic-McEliece-8192128</summary>
    ClassicMcEliece8192128,
    /// <summary>Classic-McEliece-8192128f</summary>
    ClassicMcEliece8192128f,
    /// <summary>FrodoKEM-640-AES (standard, salted variant)</summary>
    FrodoKem640Aes,
    /// <summary>FrodoKEM-640-SHAKE (standard, salted variant)</summary>
    FrodoKem640Shake,
    /// <summary>FrodoKEM-976-AES (standard, salted variant)</summary>
    FrodoKem976Aes,
    /// <summary>FrodoKEM-976-SHAKE (standard, salted variant)</summary>
    FrodoKem976Shake,
    /// <summary>FrodoKEM-1344-AES (standard, salted variant)</summary>
    FrodoKem1344Aes,
    /// <summary>FrodoKEM-1344-SHAKE (standard, salted variant)</summary>
    FrodoKem1344Shake,
    /// <summary>eFrodoKEM-640-AES (ephemeral variant)</summary>
    EFrodoKem640Aes,
    /// <summary>eFrodoKEM-640-SHAKE (ephemeral variant)</summary>
    EFrodoKem640Shake,
    /// <summary>eFrodoKEM-976-AES (ephemeral variant)</summary>
    EFrodoKem976Aes,
    /// <summary>eFrodoKEM-976-SHAKE (ephemeral variant)</summary>
    EFrodoKem976Shake,
    /// <summary>eFrodoKEM-1344-AES (ephemeral variant)</summary>
    EFrodoKem1344Aes,
    /// <summary>eFrodoKEM-1344-SHAKE (ephemeral variant)</summary>
    EFrodoKem1344Shake,
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
        KemAlgorithm.BikeL1 => Kem.OQS_KEM_alg_bike_l1,
        KemAlgorithm.BikeL3 => Kem.OQS_KEM_alg_bike_l3,
        KemAlgorithm.BikeL5 => Kem.OQS_KEM_alg_bike_l5,
        KemAlgorithm.Hqc1 => Kem.OQS_KEM_alg_hqc_1,
        KemAlgorithm.Hqc3 => Kem.OQS_KEM_alg_hqc_3,
        KemAlgorithm.Hqc5 => Kem.OQS_KEM_alg_hqc_5,
        KemAlgorithm.NtruHps2048509 => Kem.OQS_KEM_alg_ntru_hps2048509,
        KemAlgorithm.NtruHps2048677 => Kem.OQS_KEM_alg_ntru_hps2048677,
        KemAlgorithm.NtruHps4096821 => Kem.OQS_KEM_alg_ntru_hps4096821,
        KemAlgorithm.NtruHps40961229 => Kem.OQS_KEM_alg_ntru_hps40961229,
        KemAlgorithm.NtruHrss701 => Kem.OQS_KEM_alg_ntru_hrss701,
        KemAlgorithm.NtruHrss1373 => Kem.OQS_KEM_alg_ntru_hrss1373,
        KemAlgorithm.NtruPrimeSntrup761 => Kem.OQS_KEM_alg_ntruprime_sntrup761,
        KemAlgorithm.ClassicMcEliece348864 => Kem.OQS_KEM_alg_classic_mceliece_348864,
        KemAlgorithm.ClassicMcEliece348864f => Kem.OQS_KEM_alg_classic_mceliece_348864f,
        KemAlgorithm.ClassicMcEliece460896 => Kem.OQS_KEM_alg_classic_mceliece_460896,
        KemAlgorithm.ClassicMcEliece460896f => Kem.OQS_KEM_alg_classic_mceliece_460896f,
        KemAlgorithm.ClassicMcEliece6688128 => Kem.OQS_KEM_alg_classic_mceliece_6688128,
        KemAlgorithm.ClassicMcEliece6688128f => Kem.OQS_KEM_alg_classic_mceliece_6688128f,
        KemAlgorithm.ClassicMcEliece6960119 => Kem.OQS_KEM_alg_classic_mceliece_6960119,
        KemAlgorithm.ClassicMcEliece6960119f => Kem.OQS_KEM_alg_classic_mceliece_6960119f,
        KemAlgorithm.ClassicMcEliece8192128 => Kem.OQS_KEM_alg_classic_mceliece_8192128,
        KemAlgorithm.ClassicMcEliece8192128f => Kem.OQS_KEM_alg_classic_mceliece_8192128f,
        KemAlgorithm.FrodoKem640Aes => Kem.OQS_KEM_alg_frodokem_640_aes,
        KemAlgorithm.FrodoKem640Shake => Kem.OQS_KEM_alg_frodokem_640_shake,
        KemAlgorithm.FrodoKem976Aes => Kem.OQS_KEM_alg_frodokem_976_aes,
        KemAlgorithm.FrodoKem976Shake => Kem.OQS_KEM_alg_frodokem_976_shake,
        KemAlgorithm.FrodoKem1344Aes => Kem.OQS_KEM_alg_frodokem_1344_aes,
        KemAlgorithm.FrodoKem1344Shake => Kem.OQS_KEM_alg_frodokem_1344_shake,
        KemAlgorithm.EFrodoKem640Aes => Kem.OQS_KEM_alg_efrodokem_640_aes,
        KemAlgorithm.EFrodoKem640Shake => Kem.OQS_KEM_alg_efrodokem_640_shake,
        KemAlgorithm.EFrodoKem976Aes => Kem.OQS_KEM_alg_efrodokem_976_aes,
        KemAlgorithm.EFrodoKem976Shake => Kem.OQS_KEM_alg_efrodokem_976_shake,
        KemAlgorithm.EFrodoKem1344Aes => Kem.OQS_KEM_alg_efrodokem_1344_aes,
        KemAlgorithm.EFrodoKem1344Shake => Kem.OQS_KEM_alg_efrodokem_1344_shake,
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
    private readonly OqsKemHandle _handle;
    private readonly Kem.OqsKem _kem;
    private bool _disposed;

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
    /// Length of seeds for derandomized keypair generation in bytes, or 0 if the algorithm does
    /// not support derandomized keypair generation
    /// </summary>
    public int KeypairSeedLength => (int)_kem.length_keypair_seed;

    /// <summary>
    /// Length of seeds for derandomized encapsulation in bytes, or 0 if the algorithm does not
    /// support derandomized encapsulation
    /// </summary>
    public int EncapsSeedLength => (int)_kem.length_encaps_seed;

    /// <summary>
    /// Whether the algorithm supports derandomized (deterministic) keypair generation
    /// </summary>
    public bool SupportsDerandomizedKeypair => KeypairSeedLength > 0;

    /// <summary>
    /// Whether the algorithm supports derandomized (deterministic) encapsulation
    /// </summary>
    public bool SupportsDerandomizedEncapsulation => EncapsSeedLength > 0;

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

        _handle = Kem.OQS_KEM_new_handle(algorithm.GetIdentifier());
        if (_handle.IsInvalid)
        {
            _handle.Dispose();
            throw new OqsException($"Failed to create KEM instance for {algorithm}");
        }

        _kem = Marshal.PtrToStructure<Kem.OqsKem>(_handle.DangerousGetHandle());
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
    /// Generate a new keypair, optionally derandomized from <paramref name="seed"/>
    /// </summary>
    public (byte[] PublicKey, byte[] SecretKey) GenerateKeypair(byte[]? seed = null)
    {
        ThrowIfDisposed();

        if (seed != null)
        {
            if (!SupportsDerandomizedKeypair)
            {
                throw new ArgumentException(
                    $"Algorithm {Algorithm} does not support derandomized keypair generation", nameof(seed));
            }

            if (seed.Length != KeypairSeedLength)
            {
                throw new ArgumentException($"Seed must be {KeypairSeedLength} bytes", nameof(seed));
            }
        }

        var publicKey = new byte[PublicKeyLength];
        var secretKey = new byte[SecretKeyLength];

        unsafe
        {
            fixed (byte* pkPtr = publicKey, skPtr = secretKey)
            {
                Common.OqsStatus result;
                if (seed != null)
                {
                    fixed (byte* seedPtr = seed)
                    {
                        result = Kem.OQS_KEM_keypair_derand(_handle, (IntPtr)pkPtr, (IntPtr)skPtr, (IntPtr)seedPtr);
                    }
                }
                else
                {
                    result = Kem.OQS_KEM_keypair(_handle, (IntPtr)pkPtr, (IntPtr)skPtr);
                }

                if (result != Common.OqsStatus.Success)
                {
                    throw new OqsException("Failed to generate keypair");
                }
            }
        }

        return (publicKey, secretKey);
    }

    /// <summary>
    /// Encapsulate a shared secret using the public key, optionally derandomized from
    /// <paramref name="seed"/>
    /// </summary>
    public (byte[] Ciphertext, byte[] SharedSecret) Encapsulate(byte[] publicKey, byte[]? seed = null)
    {
        ThrowIfDisposed();

        if (publicKey == null)
        {
            throw new ArgumentNullException(nameof(publicKey));
        }

        if (publicKey.Length != PublicKeyLength)
        {
            throw new ArgumentException($"Public key must be {PublicKeyLength} bytes", nameof(publicKey));
        }

        if (seed != null)
        {
            if (!SupportsDerandomizedEncapsulation)
            {
                throw new ArgumentException(
                    $"Algorithm {Algorithm} does not support derandomized encapsulation", nameof(seed));
            }

            if (seed.Length != EncapsSeedLength)
            {
                throw new ArgumentException($"Seed must be {EncapsSeedLength} bytes", nameof(seed));
            }
        }

        var ciphertext = new byte[CiphertextLength];
        var sharedSecret = new byte[SharedSecretLength];

        unsafe
        {
            fixed (byte* pkPtr = publicKey, ctPtr = ciphertext, ssPtr = sharedSecret)
            {
                Common.OqsStatus result;
                if (seed != null)
                {
                    fixed (byte* seedPtr = seed)
                    {
                        result = Kem.OQS_KEM_encaps_derand(_handle, (IntPtr)ctPtr, (IntPtr)ssPtr, (IntPtr)pkPtr, (IntPtr)seedPtr);
                    }
                }
                else
                {
                    result = Kem.OQS_KEM_encaps(_handle, (IntPtr)ctPtr, (IntPtr)ssPtr, (IntPtr)pkPtr);
                }

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

        if (secretKey == null)
        {
            throw new ArgumentNullException(nameof(secretKey));
        }

        if (ciphertext == null)
        {
            throw new ArgumentNullException(nameof(ciphertext));
        }

        if (secretKey.Length != SecretKeyLength)
        {
            throw new ArgumentException($"Secret key must be {SecretKeyLength} bytes", nameof(secretKey));
        }

        if (ciphertext.Length != CiphertextLength)
        {
            throw new ArgumentException($"Ciphertext must be {CiphertextLength} bytes", nameof(ciphertext));
        }

        var sharedSecret = new byte[SharedSecretLength];

        unsafe
        {
            fixed (byte* skPtr = secretKey, ctPtr = ciphertext, ssPtr = sharedSecret)
            {
                var result = Kem.OQS_KEM_decaps(_handle, (IntPtr)ssPtr, (IntPtr)ctPtr, (IntPtr)skPtr);
                if (result != Common.OqsStatus.Success)
                {
                    throw new OqsException("Failed to decapsulate");
                }
            }
        }

        return sharedSecret;
    }

    /// <summary>
    /// Release the native KEM instance. Idempotent and safe to call from multiple threads.
    /// </summary>
    public void Dispose()
    {
        _disposed = true;
        // SafeHandle.Dispose is itself idempotent and thread-safe, and waits for any in-flight
        // P/Invoke that holds a reference to the handle.
        _handle.Dispose();
    }
}
