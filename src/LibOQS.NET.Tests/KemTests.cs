using LibOQS.NET;
using Xunit;

namespace LibOQS.NET.Tests;

public class KemTests
{

    [Theory]
    [InlineData(KemAlgorithm.MlKem512)]
    [InlineData(KemAlgorithm.MlKem768)]
    [InlineData(KemAlgorithm.MlKem1024)]
    public void KemEncapsDecaps_ShouldSucceed(KemAlgorithm algorithm)
    {
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
}
