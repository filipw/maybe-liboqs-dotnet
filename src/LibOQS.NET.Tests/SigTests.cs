using LibOQS.NET;
using Xunit;

namespace LibOQS.NET.Tests;

public class SigTests
{

    [SkippableTheory]
    [InlineData(SigAlgorithm.MlDsa44)]
    [InlineData(SigAlgorithm.MlDsa65)]
    [InlineData(SigAlgorithm.MlDsa87)]
    [InlineData(SigAlgorithm.Dilithium2)]
    [InlineData(SigAlgorithm.Dilithium3)]
    [InlineData(SigAlgorithm.Dilithium5)]
    [InlineData(SigAlgorithm.Falcon512)]
    [InlineData(SigAlgorithm.Falcon1024)]
    [InlineData(SigAlgorithm.FalconPadded512)]
    [InlineData(SigAlgorithm.FalconPadded1024)]
    [InlineData(SigAlgorithm.SphincsPlusSha2128fSimple)]
    [InlineData(SigAlgorithm.SphincsPlusSha2128sSimple)]
    [InlineData(SigAlgorithm.SphincsPlusSha2192fSimple)]
    [InlineData(SigAlgorithm.SphincsPlusSha2192sSimple)]
    [InlineData(SigAlgorithm.SphincsPlusSha2256fSimple)]
    [InlineData(SigAlgorithm.SphincsPlusSha2256sSimple)]
    [InlineData(SigAlgorithm.SphincsPlusShake128fSimple)]
    [InlineData(SigAlgorithm.SphincsPlusShake128sSimple)]
    [InlineData(SigAlgorithm.SphincsPlusShake192fSimple)]
    [InlineData(SigAlgorithm.SphincsPlusShake192sSimple)]
    [InlineData(SigAlgorithm.SphincsPlusShake256fSimple)]
    [InlineData(SigAlgorithm.SphincsPlusShake256sSimple)]
    [InlineData(SigAlgorithm.Mayo1)]
    [InlineData(SigAlgorithm.Mayo2)]
    [InlineData(SigAlgorithm.Mayo3)]
    [InlineData(SigAlgorithm.Mayo5)]
    [InlineData(SigAlgorithm.CrossRsdp128Balanced)]
    [InlineData(SigAlgorithm.CrossRsdp128Fast)]
    [InlineData(SigAlgorithm.CrossRsdp128Small)]
    [InlineData(SigAlgorithm.CrossRsdp192Balanced)]
    [InlineData(SigAlgorithm.CrossRsdp192Fast)]
    [InlineData(SigAlgorithm.CrossRsdp192Small)]
    [InlineData(SigAlgorithm.CrossRsdp256Balanced)]
    [InlineData(SigAlgorithm.CrossRsdp256Fast)]
    [InlineData(SigAlgorithm.CrossRsdp256Small)]
    [InlineData(SigAlgorithm.CrossRsdpg128Balanced)]
    [InlineData(SigAlgorithm.CrossRsdpg128Fast)]
    [InlineData(SigAlgorithm.CrossRsdpg128Small)]
    [InlineData(SigAlgorithm.CrossRsdpg192Balanced)]
    [InlineData(SigAlgorithm.CrossRsdpg192Fast)]
    [InlineData(SigAlgorithm.CrossRsdpg192Small)]
    [InlineData(SigAlgorithm.CrossRsdpg256Balanced)]
    [InlineData(SigAlgorithm.CrossRsdpg256Fast)]
    [InlineData(SigAlgorithm.CrossRsdpg256Small)]
    [InlineData(SigAlgorithm.UovOvIs)]
    [InlineData(SigAlgorithm.UovOvIp)]
    [InlineData(SigAlgorithm.UovOvIii)]
    [InlineData(SigAlgorithm.UovOvV)]
    [InlineData(SigAlgorithm.UovOvIsPkc)]
    [InlineData(SigAlgorithm.UovOvIpPkc)]
    [InlineData(SigAlgorithm.UovOvIiiPkc)]
    [InlineData(SigAlgorithm.UovOvVPkc)]
    [InlineData(SigAlgorithm.UovOvIsPkcSkc)]
    [InlineData(SigAlgorithm.UovOvIpPkcSkc)]
    [InlineData(SigAlgorithm.UovOvIiiPkcSkc)]
    [InlineData(SigAlgorithm.UovOvVPkcSkc)]
    public void SigSignVerify_ShouldSucceed(SigAlgorithm algorithm)
    {
        Skip.If(!algorithm.IsEnabled(), $"Algorithm {algorithm} is not enabled in this build.");
        using var sig = new SigInstance(algorithm);

        // Generate keypair
        var (publicKey, secretKey) = sig.GenerateKeypair();

        Assert.Equal(sig.PublicKeyLength, publicKey.Length);
        Assert.Equal(sig.SecretKeyLength, secretKey.Length);

        // Sign message
        var message = "Hello, post-quantum world!"u8.ToArray();
        var signature = sig.Sign(message, secretKey);

        Assert.True(signature.Length > 0);
        Assert.True(signature.Length <= sig.MaxSignatureLength);

        // Verify signature
        var isValid = sig.Verify(message, signature, publicKey);
        Assert.True(isValid);

        // Verify with tampered message should fail
        var tamperedMessage = "Hello, post-quantum world?"u8.ToArray();
        var isValidTampered = sig.Verify(tamperedMessage, signature, publicKey);
        Assert.False(isValidTampered);
    }

    [Fact]
    public void SigSign_WithWrongKeySize_ShouldThrow()
    {
        using var sig = new SigInstance(SigAlgorithm.MlDsa44);
        var message = "test"u8.ToArray();
        var wrongSizeKey = new byte[100]; // Wrong size

        Assert.Throws<ArgumentException>(() => sig.Sign(message, wrongSizeKey));
    }

    [Fact]
    public void SigVerify_WithWrongKeySize_ShouldThrow()
    {
        using var sig = new SigInstance(SigAlgorithm.MlDsa44);
        var message = "test"u8.ToArray();
        var signature = new byte[100];
        var wrongSizeKey = new byte[100]; // Wrong size

        Assert.Throws<ArgumentException>(() => sig.Verify(message, signature, wrongSizeKey));
    }

    [Fact]
    public void SigDispose_ShouldAllowMultipleCalls()
    {
        var sig = new SigInstance(SigAlgorithm.MlDsa44);

        sig.Dispose();
        sig.Dispose(); // Should not throw
    }

    [Fact]
    public void SigUseAfterDispose_ShouldThrow()
    {
        var sig = new SigInstance(SigAlgorithm.MlDsa44);
        sig.Dispose();

        Assert.Throws<ObjectDisposedException>(() => sig.GenerateKeypair());
    }

    [Fact]
    public void SigEmptyMessage_ShouldWork()
    {
        using var sig = new SigInstance(SigAlgorithm.MlDsa44);
        var (publicKey, secretKey) = sig.GenerateKeypair();

        var emptyMessage = Array.Empty<byte>();
        var signature = sig.Sign(emptyMessage, secretKey);
        var isValid = sig.Verify(emptyMessage, signature, publicKey);

        Assert.True(isValid);
    }

    [SkippableTheory]
    [InlineData(SigAlgorithm.Dilithium2)]
    [InlineData(SigAlgorithm.Dilithium3)]
    [InlineData(SigAlgorithm.Dilithium5)]
    public void DilithiumSignVerify_ShouldSucceed(SigAlgorithm algorithm)
    {
        Skip.If(!algorithm.IsEnabled(), $"Algorithm {algorithm} is not enabled in this build.");
        using var sig = new SigInstance(algorithm);

        // Generate keypair
        var (publicKey, secretKey) = sig.GenerateKeypair();

        Assert.Equal(sig.PublicKeyLength, publicKey.Length);
        Assert.Equal(sig.SecretKeyLength, secretKey.Length);

        // Test with various message sizes
        var testMessages = new[]
        {
            Array.Empty<byte>(),
            "Small message"u8.ToArray(),
            new byte[1024], // Medium message
            new byte[10000] // Large message
        };

        foreach (var message in testMessages)
        {
            var signature = sig.Sign(message, secretKey);
            Assert.True(signature.Length > 0);
            Assert.True(signature.Length <= sig.MaxSignatureLength);

            var isValid = sig.Verify(message, signature, publicKey);
            Assert.True(isValid);
        }
    }

    [SkippableTheory]
    [InlineData(SigAlgorithm.Falcon512)]
    [InlineData(SigAlgorithm.Falcon1024)]
    public void FalconSignVerify_ShouldSucceed(SigAlgorithm algorithm)
    {
        Skip.If(!algorithm.IsEnabled(), $"Algorithm {algorithm} is not enabled in this build.");
        using var sig = new SigInstance(algorithm);

        // Generate keypair
        var (publicKey, secretKey) = sig.GenerateKeypair();

        Assert.Equal(sig.PublicKeyLength, publicKey.Length);
        Assert.Equal(sig.SecretKeyLength, secretKey.Length);

        var message = "Falcon test message"u8.ToArray();
        var signature1 = sig.Sign(message, secretKey);
        var signature2 = sig.Sign(message, secretKey);

        // Both signatures should be valid
        Assert.True(sig.Verify(message, signature1, publicKey));
        Assert.True(sig.Verify(message, signature2, publicKey));

        // Test signature length consistency
        Assert.True(signature1.Length <= sig.MaxSignatureLength);
        Assert.True(signature2.Length <= sig.MaxSignatureLength);
    }

    [Fact]
    public void SigAlgorithmIsEnabled_ShouldReturnConsistentResults()
    {
        var allAlgorithms = Enum.GetValues<SigAlgorithm>();

        foreach (var algorithm in allAlgorithms)
        {
            if (algorithm.IsEnabled())
            {
                // If enabled, should be able to create instance
                using var sig = new SigInstance(algorithm);
                Assert.NotNull(sig);
            }
        }
    }

    [SkippableTheory]
    [InlineData(SigAlgorithm.MlDsa44)]
    [InlineData(SigAlgorithm.Dilithium2)]
    [InlineData(SigAlgorithm.Falcon512)]
    [InlineData(SigAlgorithm.FalconPadded512)]
    [InlineData(SigAlgorithm.SphincsPlusSha2128fSimple)]
    [InlineData(SigAlgorithm.Mayo1)]
    [InlineData(SigAlgorithm.CrossRsdp128Balanced)]
    [InlineData(SigAlgorithm.UovOvIs)]
    public void SigKeyLengths_ShouldBeConsistent(SigAlgorithm algorithm)
    {
        Skip.If(!algorithm.IsEnabled(), $"Algorithm {algorithm} is not enabled in this build.");
        using var sig = new SigInstance(algorithm);

        // Key lengths should be positive
        Assert.True(sig.PublicKeyLength > 0);
        Assert.True(sig.SecretKeyLength > 0);
        Assert.True(sig.MaxSignatureLength > 0);

        // Generated keys should match reported lengths
        var (publicKey, secretKey) = sig.GenerateKeypair();
        Assert.Equal(sig.PublicKeyLength, publicKey.Length);
        Assert.Equal(sig.SecretKeyLength, secretKey.Length);
    }

    [Fact]
    public void SigDifferentAlgorithms_ShouldNotCrossVerify()
    {
        var enabledAlgorithms = Enum.GetValues<SigAlgorithm>()
            .Where(alg => alg.IsEnabled())
            .Take(2)
            .ToArray();

        if (enabledAlgorithms.Length < 2)
        {
            // Skip if less than 2 algorithms are enabled
            return;
        }

        using var sig1 = new SigInstance(enabledAlgorithms[0]);
        using var sig2 = new SigInstance(enabledAlgorithms[1]);

        var (pk1, sk1) = sig1.GenerateKeypair();
        var (pk2, sk2) = sig2.GenerateKeypair();

        var message = "Cross-algorithm test"u8.ToArray();
        var signature1 = sig1.Sign(message, sk1);

        // Should not verify with different algorithm's key
        if (pk2.Length == pk1.Length) // Only test if key sizes match
        {
            var isValid = sig2.Verify(message, signature1, pk2);
            Assert.False(isValid);
        }
    }

    [SkippableTheory]
    [InlineData(SigAlgorithm.MlDsa44)]
    [InlineData(SigAlgorithm.Dilithium2)]
    public void SigLargeMessage_ShouldWork(SigAlgorithm algorithm)
    {
        Skip.If(!algorithm.IsEnabled(), $"Algorithm {algorithm} is not enabled in this build.");
        using var sig = new SigInstance(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeypair();

        // Test with very large message (1MB)
        var largeMessage = new byte[1024 * 1024];
        new Random(42).NextBytes(largeMessage); // Deterministic random data

        var signature = sig.Sign(largeMessage, secretKey);
        var isValid = sig.Verify(largeMessage, signature, publicKey);

        Assert.True(isValid);
    }

    [Fact]
    public void SigNullMessage_ShouldThrow()
    {
        if (!SigAlgorithm.MlDsa44.IsEnabled())
        {
            return;
        }

        using var sig = new SigInstance(SigAlgorithm.MlDsa44);
        var (publicKey, secretKey) = sig.GenerateKeypair();
        var signature = new byte[100];

        Assert.Throws<NullReferenceException>(() => sig.Sign(null!, secretKey));
        Assert.Throws<NullReferenceException>(() => sig.Verify(null!, signature, publicKey));
    }

    [Fact]
    public void SigNullKeys_ShouldThrow()
    {
        using var sig = new SigInstance(SigAlgorithm.MlDsa44);
        var message = "test"u8.ToArray();
        var signature = new byte[100];
        var publicKey = new byte[sig.PublicKeyLength];

        Assert.Throws<NullReferenceException>(() => sig.Sign(message, null!));
        Assert.Throws<NullReferenceException>(() => sig.Verify(message, signature, null!));
        Assert.Throws<NullReferenceException>(() => sig.Verify(message, null!, publicKey));
    }

    [Fact]
    public void SigVerify_WithInvalidSignature_ShouldReturnFalse()
    {
        using var sig = new SigInstance(SigAlgorithm.MlDsa44);
        var (publicKey, secretKey) = sig.GenerateKeypair();
        var message = "test message"u8.ToArray();

        // Create invalid signature (all zeros)
        var invalidSignature = new byte[100];

        var isValid = sig.Verify(message, invalidSignature, publicKey);
        Assert.False(isValid);
    }

    [Fact]
    public void SigSign_WithTamperedSecretKey_ShouldFail()
    {
        using var sig = new SigInstance(SigAlgorithm.MlDsa44);
        var (publicKey, secretKey) = sig.GenerateKeypair();
        var message = "test message"u8.ToArray();

        // Tamper with secret key
        var tamperedSecretKey = (byte[])secretKey.Clone();
        tamperedSecretKey[0] ^= 0xFF; // Flip bits in first byte

        var signature = sig.Sign(message, tamperedSecretKey);
        var isValid = sig.Verify(message, signature, publicKey);

        // Should either throw during signing or produce invalid signature
        Assert.False(isValid);
    }

    [SkippableTheory]
    [InlineData(SigAlgorithm.MlDsa44)]
    [InlineData(SigAlgorithm.MlDsa65)]
    [InlineData(SigAlgorithm.MlDsa87)]
    public void MlDsaAlgorithms_ShouldHaveCorrectSecurityLevels(SigAlgorithm algorithm)
    {
        Skip.If(!algorithm.IsEnabled(), $"Algorithm {algorithm} is not enabled in this build.");
        using var sig = new SigInstance(algorithm);

        // ML-DSA algorithms should have progressively larger keys and signatures
        switch (algorithm)
        {
            case SigAlgorithm.MlDsa44:
                // ML-DSA-44 should be the smallest
                Assert.True(sig.PublicKeyLength > 0);
                Assert.True(sig.SecretKeyLength > 0);
                break;
            case SigAlgorithm.MlDsa65:
                // ML-DSA-65 should be larger than 44
                Assert.True(sig.PublicKeyLength > 1000);
                Assert.True(sig.SecretKeyLength > 2000);
                break;
            case SigAlgorithm.MlDsa87:
                // ML-DSA-87 should be the largest
                Assert.True(sig.PublicKeyLength > 1500);
                Assert.True(sig.SecretKeyLength > 3000);
                break;
        }
    }

    [SkippableTheory]
    [InlineData(SigAlgorithm.Falcon512)]
    [InlineData(SigAlgorithm.Falcon1024)]
    [InlineData(SigAlgorithm.FalconPadded512)]
    [InlineData(SigAlgorithm.FalconPadded1024)]
    public void FalconAlgorithms_ShouldHaveCompactSignatures(SigAlgorithm algorithm)
    {
        Skip.If(!algorithm.IsEnabled(), $"Algorithm {algorithm} is not enabled in this build.");
        using var sig = new SigInstance(algorithm);
        var (publicKey, secretKey) = sig.GenerateKeypair();
        var message = "Falcon signature test"u8.ToArray();

        var signature = sig.Sign(message, secretKey);

        // Falcon is known for compact signatures
        // Signature should be much smaller than SPHINCS+ variants
        Assert.True(signature.Length < 2000, $"Falcon signature too large: {signature.Length} bytes");

        // Verify the signature works
        Assert.True(sig.Verify(message, signature, publicKey));
    }

    [Fact]
    public void SigMultipleInstances_ShouldWorkIndependently()
    {
        using var sig1 = new SigInstance(SigAlgorithm.MlDsa44);
        using var sig2 = new SigInstance(SigAlgorithm.Dilithium2);

        var (pk1, sk1) = sig1.GenerateKeypair();
        var (pk2, sk2) = sig2.GenerateKeypair();

        var message1 = "Message for MlDsa44"u8.ToArray();
        var message2 = "Message for Dilithium2"u8.ToArray();

        var signature1 = sig1.Sign(message1, sk1);
        var signature2 = sig2.Sign(message2, sk2);

        // Each should verify with its own keys
        Assert.True(sig1.Verify(message1, signature1, pk1));
        Assert.True(sig2.Verify(message2, signature2, pk2));
    }

    [Fact]
    public async Task SigThreadSafety_MultipleKeypairGeneration()
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
                    using var sig = new SigInstance(SigAlgorithm.MlDsa44);
                    for (int j = 0; j < operationsPerThread; j++)
                    {
                        var (pk, sk) = sig.GenerateKeypair();
                        var message = System.Text.Encoding.UTF8.GetBytes($"Thread {threadIndex} operation {j}");
                        var signature = sig.Sign(message, sk);
                        var isValid = sig.Verify(message, signature, pk);

                        if (!isValid)
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

        // All threads should succeed
        foreach (var result in results)
        {
            Assert.True(result);
        }
    }
}
