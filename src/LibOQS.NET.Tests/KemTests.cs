using LibOQS.NET;
using Xunit;

namespace LibOQS.NET.Tests;

public class KemTests
{

    [SkippableTheory]
    [InlineData(KemAlgorithm.MlKem512)]
    [InlineData(KemAlgorithm.MlKem768)]
    [InlineData(KemAlgorithm.MlKem1024)]
    [InlineData(KemAlgorithm.Kyber512)]
    [InlineData(KemAlgorithm.Kyber768)]
    [InlineData(KemAlgorithm.Kyber1024)]
    [InlineData(KemAlgorithm.BikeL1)]
    [InlineData(KemAlgorithm.BikeL3)]
    [InlineData(KemAlgorithm.BikeL5)]
    [InlineData(KemAlgorithm.Hqc128)]
    [InlineData(KemAlgorithm.Hqc192)]
    [InlineData(KemAlgorithm.Hqc256)]
    [InlineData(KemAlgorithm.NtruHps2048509)]
    [InlineData(KemAlgorithm.NtruHps2048677)]
    [InlineData(KemAlgorithm.NtruHps4096821)]
    [InlineData(KemAlgorithm.NtruHps40961229)]
    [InlineData(KemAlgorithm.NtruHrss701)]
    [InlineData(KemAlgorithm.NtruHrss1373)]
    [InlineData(KemAlgorithm.NtruPrimeSntrup761)]
    // [InlineData(KemAlgorithm.ClassicMcEliece348864)]
    // [InlineData(KemAlgorithm.ClassicMcEliece348864f)]
    // [InlineData(KemAlgorithm.ClassicMcEliece460896)]
    // [InlineData(KemAlgorithm.ClassicMcEliece460896f)]
    // [InlineData(KemAlgorithm.ClassicMcEliece6688128)]
    // [InlineData(KemAlgorithm.ClassicMcEliece6688128f)]
    // [InlineData(KemAlgorithm.ClassicMcEliece6960119)]
    // [InlineData(KemAlgorithm.ClassicMcEliece6960119f)]
    // [InlineData(KemAlgorithm.ClassicMcEliece8192128)]
    // [InlineData(KemAlgorithm.ClassicMcEliece8192128f)]
    [InlineData(KemAlgorithm.FrodoKem640Aes)]
    [InlineData(KemAlgorithm.FrodoKem640Shake)]
    [InlineData(KemAlgorithm.FrodoKem976Aes)]
    [InlineData(KemAlgorithm.FrodoKem976Shake)]
    [InlineData(KemAlgorithm.FrodoKem1344Aes)]
    [InlineData(KemAlgorithm.FrodoKem1344Shake)]
    public void KemEncapsDecaps_ShouldSucceed(KemAlgorithm algorithm)
    {
        Skip.If(!algorithm.IsEnabled(), $"Algorithm {algorithm} is not enabled in this build.");
        using var kem = new KemInstance(algorithm);

        // Generate keypair
        var (publicKey, secretKey) = kem.GenerateKeypair();

        Assert.Equal(kem.PublicKeyLength, publicKey.Length);
        Assert.Equal(kem.SecretKeyLength, secretKey.Length);

        // Encapsulate
        var (ciphertext, sharedSecret1) = kem.Encapsulate(publicKey);

        Assert.Equal(kem.CiphertextLength, ciphertext.Length);
        Assert.Equal(kem.SharedSecretLength, sharedSecret1.Length);

        // Decapsulate
        var sharedSecret2 = kem.Decapsulate(secretKey, ciphertext);

        Assert.Equal(kem.SharedSecretLength, sharedSecret2.Length);
        Assert.Equal(sharedSecret1, sharedSecret2);
    }

    [Fact]
    public void KemEncapsulate_WithWrongKeySize_ShouldThrow()
    {
        using var kem = new KemInstance(KemAlgorithm.MlKem512);
        var wrongSizeKey = new byte[100]; // Wrong size

        Assert.Throws<ArgumentException>(() => kem.Encapsulate(wrongSizeKey));
    }

    [Fact]
    public void KemDecapsulate_WithWrongKeySize_ShouldThrow()
    {
        using var kem = new KemInstance(KemAlgorithm.MlKem512);
        var (publicKey, _) = kem.GenerateKeypair();
        var (ciphertext, _) = kem.Encapsulate(publicKey);

        var wrongSizeKey = new byte[100]; // Wrong size

        Assert.Throws<ArgumentException>(() => kem.Decapsulate(wrongSizeKey, ciphertext));
    }

    [Fact]
    public void KemDecapsulate_WithWrongCiphertextSize_ShouldThrow()
    {
        using var kem = new KemInstance(KemAlgorithm.MlKem512);
        var (_, secretKey) = kem.GenerateKeypair();

        var wrongSizeCiphertext = new byte[100]; // Wrong size

        Assert.Throws<ArgumentException>(() => kem.Decapsulate(secretKey, wrongSizeCiphertext));
    }

    [Fact]
    public void KemDispose_ShouldAllowMultipleCalls()
    {
        var kem = new KemInstance(KemAlgorithm.MlKem512);

        kem.Dispose();
        kem.Dispose(); // Should not throw
    }

    [Fact]
    public void KemUseAfterDispose_ShouldThrow()
    {
        var kem = new KemInstance(KemAlgorithm.MlKem512);
        kem.Dispose();

        Assert.Throws<ObjectDisposedException>(() => kem.GenerateKeypair());
    }

    [SkippableTheory]
    [InlineData(KemAlgorithm.Kyber512)]
    [InlineData(KemAlgorithm.Kyber768)]
    [InlineData(KemAlgorithm.Kyber1024)]
    public void KyberKem_ShouldSucceed(KemAlgorithm algorithm)
    {
        Skip.If(!algorithm.IsEnabled(), $"Algorithm {algorithm} is not enabled in this build.");
        using var kem = new KemInstance(algorithm);

        // Generate keypair
        var (publicKey, secretKey) = kem.GenerateKeypair();

        Assert.Equal(kem.PublicKeyLength, publicKey.Length);
        Assert.Equal(kem.SecretKeyLength, secretKey.Length);

        // Test multiple encapsulations with same keys
        for (int i = 0; i < 5; i++)
        {
            var (ciphertext, sharedSecret1) = kem.Encapsulate(publicKey);
            var sharedSecret2 = kem.Decapsulate(secretKey, ciphertext);

            Assert.Equal(kem.CiphertextLength, ciphertext.Length);
            Assert.Equal(kem.SharedSecretLength, sharedSecret1.Length);
            Assert.Equal(kem.SharedSecretLength, sharedSecret2.Length);
            Assert.Equal(sharedSecret1, sharedSecret2);
        }
    }

    [SkippableTheory]
    [InlineData(KemAlgorithm.FrodoKem640Aes)]
    [InlineData(KemAlgorithm.FrodoKem640Shake)]
    [InlineData(KemAlgorithm.FrodoKem976Aes)]
    [InlineData(KemAlgorithm.FrodoKem976Shake)]
    [InlineData(KemAlgorithm.FrodoKem1344Aes)]
    [InlineData(KemAlgorithm.FrodoKem1344Shake)]
    public void FrodoKem_ShouldSucceed(KemAlgorithm algorithm)
    {
        Skip.If(!algorithm.IsEnabled(), $"Algorithm {algorithm} is not enabled in this build.");
        using var kem = new KemInstance(algorithm);

        // Generate keypair
        var (publicKey, secretKey) = kem.GenerateKeypair();

        Assert.Equal(kem.PublicKeyLength, publicKey.Length);
        Assert.Equal(kem.SecretKeyLength, secretKey.Length);

        // FrodoKEM typically has larger key sizes than other algorithms
        Assert.True(kem.PublicKeyLength > 1000, $"FrodoKEM public key should be large: {kem.PublicKeyLength}");
        Assert.True(kem.SecretKeyLength > 1000, $"FrodoKEM secret key should be large: {kem.SecretKeyLength}");

        // Test encapsulation/decapsulation
        var (ciphertext, sharedSecret1) = kem.Encapsulate(publicKey);
        var sharedSecret2 = kem.Decapsulate(secretKey, ciphertext);

        Assert.Equal(sharedSecret1, sharedSecret2);
    }

    [SkippableTheory]
    [InlineData(KemAlgorithm.MlKem512)]
    [InlineData(KemAlgorithm.Kyber512)]
    [InlineData(KemAlgorithm.BikeL1)]
    [InlineData(KemAlgorithm.Hqc128)]
    [InlineData(KemAlgorithm.NtruHps2048509)]
    [InlineData(KemAlgorithm.NtruPrimeSntrup761)]
    // [InlineData(KemAlgorithm.ClassicMcEliece348864)]
    [InlineData(KemAlgorithm.FrodoKem640Aes)]
    public void KemKeyLengths_ShouldBeConsistent(KemAlgorithm algorithm)
    {
        Skip.If(!algorithm.IsEnabled(), $"Algorithm {algorithm} is not enabled in this build.");
        using var kem = new KemInstance(algorithm);

        Assert.True(kem.PublicKeyLength > 0);
        Assert.True(kem.SecretKeyLength > 0);
        Assert.True(kem.CiphertextLength > 0);
        Assert.True(kem.SharedSecretLength > 0);

        // Generated keys should match reported lengths
        var (publicKey, secretKey) = kem.GenerateKeypair();
        Assert.Equal(kem.PublicKeyLength, publicKey.Length);
        Assert.Equal(kem.SecretKeyLength, secretKey.Length);

        // Encapsulation should produce correct lengths
        var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
        Assert.Equal(kem.CiphertextLength, ciphertext.Length);
        Assert.Equal(kem.SharedSecretLength, sharedSecret.Length);
    }

    [SkippableTheory]
    [InlineData(KemAlgorithm.MlKem512)]
    [InlineData(KemAlgorithm.MlKem768)]
    [InlineData(KemAlgorithm.MlKem1024)]
    public void MlKemAlgorithms_ShouldHaveProgressiveSizes(KemAlgorithm algorithm)
    {
        Skip.If(!algorithm.IsEnabled(), $"Algorithm {algorithm} is not enabled in this build.");
        using var kem = new KemInstance(algorithm);

        // ML-KEM algorithms should have progressively larger key sizes
        switch (algorithm)
        {
            case KemAlgorithm.MlKem512:
                Assert.True(kem.PublicKeyLength > 700 && kem.PublicKeyLength < 1000);
                Assert.True(kem.SecretKeyLength > 1500 && kem.SecretKeyLength < 2000);
                break;
            case KemAlgorithm.MlKem768:
                Assert.True(kem.PublicKeyLength > 1000 && kem.PublicKeyLength < 1300);
                Assert.True(kem.SecretKeyLength > 2300 && kem.SecretKeyLength < 2700);
                break;
            case KemAlgorithm.MlKem1024:
                Assert.True(kem.PublicKeyLength > 1500);
                Assert.True(kem.SecretKeyLength > 3000);
                break;
        }

        Assert.Equal(32, kem.SharedSecretLength);
    }

    [Fact]
    public void KemMultipleInstances_ShouldWorkIndependently()
    {
        using var kem1 = new KemInstance(KemAlgorithm.MlKem512);
        using var kem2 = new KemInstance(KemAlgorithm.Kyber512);

        var (pk1, sk1) = kem1.GenerateKeypair();
        var (pk2, sk2) = kem2.GenerateKeypair();

        var (ct1, ss1_enc) = kem1.Encapsulate(pk1);
        var (ct2, ss2_enc) = kem2.Encapsulate(pk2);

        var ss1_dec = kem1.Decapsulate(sk1, ct1);
        var ss2_dec = kem2.Decapsulate(sk2, ct2);

        // Each should work with its own keys
        Assert.Equal(ss1_enc, ss1_dec);
        Assert.Equal(ss2_enc, ss2_dec);
    }

    [Fact]
    public void KemNull_ShouldThrow()
    {
        using var kem = new KemInstance(KemAlgorithm.MlKem512);
        var (publicKey, secretKey) = kem.GenerateKeypair();
        var (ciphertext, _) = kem.Encapsulate(publicKey);

        Assert.Throws<NullReferenceException>(() => kem.Encapsulate(null!));
        Assert.Throws<NullReferenceException>(() => kem.Decapsulate(null!, ciphertext));
        Assert.Throws<NullReferenceException>(() => kem.Decapsulate(secretKey, null!));
    }

    [Fact]
    public void KemRandomness_EncapsulationsShouldBeDifferent()
    {
        using var kem = new KemInstance(KemAlgorithm.MlKem512);
        var (publicKey, secretKey) = kem.GenerateKeypair();

        // Multiple encapsulations should produce different ciphertexts but recoverable shared secrets
        var results = new List<(byte[] ciphertext, byte[] sharedSecret)>();

        for (int i = 0; i < 5; i++)
        {
            var (ct, ss) = kem.Encapsulate(publicKey);
            results.Add((ct, ss));

            // Verify decapsulation works
            var recoveredSS = kem.Decapsulate(secretKey, ct);
            Assert.Equal(ss, recoveredSS);
        }

        // All ciphertexts should be different
        for (int i = 0; i < results.Count; i++)
        {
            for (int j = i + 1; j < results.Count; j++)
            {
                Assert.NotEqual(results[i].ciphertext, results[j].ciphertext);

                // Shared secrets should also be different
                Assert.NotEqual(results[i].sharedSecret, results[j].sharedSecret);
            }
        }
    }

    [Fact]
    public async Task KemThreadSafety_MultipleOperations()
    {
        const int threadCount = 4;
        const int operationsPerThread = 5;
        var results = new bool[threadCount];
        var tasks = new Task[threadCount];

        for (int i = 0; i < threadCount; i++)
        {
            int threadIndex = i;
            tasks[i] = Task.Run(() =>
            {
                try
                {
                    using var kem = new KemInstance(KemAlgorithm.MlKem512);
                    for (int j = 0; j < operationsPerThread; j++)
                    {
                        var (pk, sk) = kem.GenerateKeypair();
                        var (ct, ss1) = kem.Encapsulate(pk);
                        var ss2 = kem.Decapsulate(sk, ct);

                        if (!ss1.SequenceEqual(ss2))
                        {
                            results[threadIndex] = false;
                            return;
                        }
                    }
                    results[threadIndex] = true;
                }
                catch
                {
                    results[threadIndex] = false;
                }
            });
        }

        await Task.WhenAll(tasks);

        foreach (var result in results)
        {
            Assert.True(result);
        }
    }

    [SkippableTheory]
    [InlineData(KemAlgorithm.FrodoKem640Aes, KemAlgorithm.FrodoKem640Shake)]
    [InlineData(KemAlgorithm.FrodoKem976Aes, KemAlgorithm.FrodoKem976Shake)]
    [InlineData(KemAlgorithm.FrodoKem1344Aes, KemAlgorithm.FrodoKem1344Shake)]
    public void FrodoKemVariants_ShouldHaveSameSizes(KemAlgorithm aesVariant, KemAlgorithm shakeVariant)
    {
        if (!aesVariant.IsEnabled() || !shakeVariant.IsEnabled()) return;
        using var kemAes = new KemInstance(aesVariant);
        using var kemShake = new KemInstance(shakeVariant);

        // AES and SHAKE variants of the same FrodoKEM should have same key sizes
        Assert.Equal(kemAes.PublicKeyLength, kemShake.PublicKeyLength);
        Assert.Equal(kemAes.SecretKeyLength, kemShake.SecretKeyLength);
        Assert.Equal(kemAes.CiphertextLength, kemShake.CiphertextLength);
        Assert.Equal(kemAes.SharedSecretLength, kemShake.SharedSecretLength);

        var (pkAes, skAes) = kemAes.GenerateKeypair();
        var (pkShake, skShake) = kemShake.GenerateKeypair();

        var (ctAes, ssAes1) = kemAes.Encapsulate(pkAes);
        var (ctShake, ssShake1) = kemShake.Encapsulate(pkShake);

        var ssAes2 = kemAes.Decapsulate(skAes, ctAes);
        var ssShake2 = kemShake.Decapsulate(skShake, ctShake);

        Assert.Equal(ssAes1, ssAes2);
        Assert.Equal(ssShake1, ssShake2);
    }
    [SkippableTheory]
    [InlineData(KemAlgorithm.MlKem512)]
    public void KemDerandomized_ShouldBeDeterministic(KemAlgorithm algorithm)
    {
        Skip.If(!algorithm.IsEnabled(), $"Algorithm {algorithm} is not enabled in this build.");
        using var kem = new KemInstance(algorithm);
        Skip.If(kem.KeypairSeedLength == 0, $"Algorithm {algorithm} does not support derandomized keypair.");

        var seed = new byte[kem.KeypairSeedLength];
        new Random(42).NextBytes(seed);

        // Generate keypair twice with same seed
        var (pk1, sk1) = kem.GenerateKeypair(seed);
        var (pk2, sk2) = kem.GenerateKeypair(seed);

        Assert.Equal(pk1, pk2);
        Assert.Equal(sk1, sk2);

        // Encapsulate twice with same seed
        if (kem.EncapsSeedLength > 0)
        {
            var encapsSeed = new byte[kem.EncapsSeedLength];
            new Random(123).NextBytes(encapsSeed);

            var (ct1, ss1) = kem.Encapsulate(pk1, encapsSeed);
            var (ct2, ss2) = kem.Encapsulate(pk1, encapsSeed);

            Assert.Equal(ct1, ct2);
            Assert.Equal(ss1, ss2);
        }
    }
}
