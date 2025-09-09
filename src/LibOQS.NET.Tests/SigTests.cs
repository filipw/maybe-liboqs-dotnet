using LibOQS.NET;
using Xunit;

namespace LibOQS.NET.Tests;

public class SigTests
{

    [Theory]
    [InlineData(SigAlgorithm.MlDsa44)]
    [InlineData(SigAlgorithm.MlDsa65)]
    [InlineData(SigAlgorithm.MlDsa87)]
    public void SigSignVerify_ShouldSucceed(SigAlgorithm algorithm)
    {
        // Skip test if algorithm is not enabled
        if (!algorithm.IsEnabled())
        {
            return;
        }

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
        if (!SigAlgorithm.MlDsa44.IsEnabled())
        {
            return;
        }

        using var sig = new SigInstance(SigAlgorithm.MlDsa44);
        var message = "test"u8.ToArray();
        var wrongSizeKey = new byte[100]; // Wrong size
        
        Assert.Throws<ArgumentException>(() => sig.Sign(message, wrongSizeKey));
    }

    [Fact]
    public void SigVerify_WithWrongKeySize_ShouldThrow()
    {
        if (!SigAlgorithm.MlDsa44.IsEnabled())
        {
            return;
        }

        using var sig = new SigInstance(SigAlgorithm.MlDsa44);
        var message = "test"u8.ToArray();
        var signature = new byte[100];
        var wrongSizeKey = new byte[100]; // Wrong size
        
        Assert.Throws<ArgumentException>(() => sig.Verify(message, signature, wrongSizeKey));
    }

    [Fact]
    public void SigDispose_ShouldAllowMultipleCalls()
    {
        if (!SigAlgorithm.MlDsa44.IsEnabled())
        {
            return;
        }

        var sig = new SigInstance(SigAlgorithm.MlDsa44);
        
        sig.Dispose();
        sig.Dispose(); // Should not throw
    }

    [Fact]
    public void SigUseAfterDispose_ShouldThrow()
    {
        if (!SigAlgorithm.MlDsa44.IsEnabled())
        {
            return;
        }

        var sig = new SigInstance(SigAlgorithm.MlDsa44);
        sig.Dispose();
        
        Assert.Throws<ObjectDisposedException>(() => sig.GenerateKeypair());
    }

    [Fact]
    public void SigEmptyMessage_ShouldWork()
    {
        if (!SigAlgorithm.MlDsa44.IsEnabled())
        {
            return;
        }

        using var sig = new SigInstance(SigAlgorithm.MlDsa44);
        var (publicKey, secretKey) = sig.GenerateKeypair();
        
        var emptyMessage = Array.Empty<byte>();
        var signature = sig.Sign(emptyMessage, secretKey);
        var isValid = sig.Verify(emptyMessage, signature, publicKey);
        
        Assert.True(isValid);
    }
}
