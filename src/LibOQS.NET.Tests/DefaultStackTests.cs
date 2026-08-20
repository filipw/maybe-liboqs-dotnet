using LibOQS.NET;
using Xunit;

namespace LibOQS.NET.Tests;

/// <summary>
/// Algorithms that must work on an ordinary thread, with no help from <see cref="LargeStack"/>.
/// </summary>
/// <remarks>
/// Every other algorithm test runs inside a generously sized thread so it measures the algorithm
/// rather than the ambient stack. That is deliberate, but it means those tests cannot detect a
/// platform whose default thread stack is too small - and the platforms differ a lot. .NET gives
/// non-main threads roughly 1.5 MB on musl (Alpine) against roughly 8 MB on glibc.
///
/// These tests deliberately run on a plain thread pool thread, the same place an ASP.NET request
/// handler or a Task.Run callback executes, so that a platform which cannot host the common
/// algorithms fails here rather than in a consumer's container. Keep this list to parameter sets
/// that fit comfortably everywhere; genuinely heavy ones are documented as needing a caller-sized
/// thread and belong in the LargeStack-wrapped tests instead.
///
/// A stack overflow is fail-fast, so a regression here crashes the test host rather than failing
/// an assertion. That is louder than it is pretty, and it is the point.
/// </remarks>
public class DefaultStackTests
{
    private static void OnThreadPoolThread(Action body)
    {
        Exception? failure = null;
        using var done = new ManualResetEventSlim(false);

        ThreadPool.QueueUserWorkItem(_ =>
        {
            try
            {
                body();
            }
            catch (Exception ex)
            {
                failure = ex;
            }
            finally
            {
                done.Set();
            }
        });

        Assert.True(done.Wait(TimeSpan.FromMinutes(2)), "Operation did not complete");
        if (failure != null)
        {
            throw failure;
        }
    }

    [SkippableTheory]
    [InlineData(SigAlgorithm.MlDsa44)]
    [InlineData(SigAlgorithm.MlDsa65)]
    [InlineData(SigAlgorithm.MlDsa87)]
    [InlineData(SigAlgorithm.Falcon512)]
    [InlineData(SigAlgorithm.Falcon1024)]
    [InlineData(SigAlgorithm.Mayo1)]
    [InlineData(SigAlgorithm.Mayo2)]
    [InlineData(SigAlgorithm.CrossRsdp128Balanced)]
    [InlineData(SigAlgorithm.CrossRsdpg128Balanced)]
    [InlineData(SigAlgorithm.UovOvIs)]
    [InlineData(SigAlgorithm.Snova24_5_4)]
    [InlineData(SigAlgorithm.Mqom2Cat1Gf16FastR3)]
    // The MQOM "short" sets need the memory-optimized build to fit here. They regressed on musl
    // because only the Windows and macOS builds passed OQS_MEMOPT_BUILD.
    [InlineData(SigAlgorithm.Mqom2Cat1Gf16ShortR3)]
    [InlineData(SigAlgorithm.Mqom2Cat3Gf16ShortR3)]
    [InlineData(SigAlgorithm.Mqom2Cat5Gf16ShortR5)]
    public void Sig_ShouldWorkOnADefaultThread(SigAlgorithm algorithm)
    {
        Skip.If(!algorithm.IsEnabled(), $"Algorithm {algorithm} is not enabled in this build.");

        OnThreadPoolThread(() =>
        {
            using var sig = new SigInstance(algorithm);
            var (publicKey, secretKey) = sig.GenerateKeypair();
            var message = "default stack probe"u8.ToArray();
            var signature = sig.Sign(message, secretKey);
            Assert.True(sig.Verify(message, signature, publicKey));
        });
    }

    [SkippableTheory]
    [InlineData(KemAlgorithm.MlKem512)]
    [InlineData(KemAlgorithm.MlKem768)]
    [InlineData(KemAlgorithm.MlKem1024)]
    [InlineData(KemAlgorithm.Kyber512)]
    [InlineData(KemAlgorithm.Hqc1)]
    [InlineData(KemAlgorithm.FrodoKem640Aes)]
    [InlineData(KemAlgorithm.EFrodoKem640Aes)]
    [InlineData(KemAlgorithm.NtruHps2048509)]
    [InlineData(KemAlgorithm.NtruPrimeSntrup761)]
    [InlineData(KemAlgorithm.ClassicMcEliece348864)]
    public void Kem_ShouldWorkOnADefaultThread(KemAlgorithm algorithm)
    {
        Skip.If(!algorithm.IsEnabled(), $"Algorithm {algorithm} is not enabled in this build.");

        OnThreadPoolThread(() =>
        {
            using var kem = new KemInstance(algorithm);
            var (publicKey, secretKey) = kem.GenerateKeypair();
            var (ciphertext, sharedSecret) = kem.Encapsulate(publicKey);
            Assert.Equal(sharedSecret, kem.Decapsulate(secretKey, ciphertext));
        });
    }
}
