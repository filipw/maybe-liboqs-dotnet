using LibOQS.NET;
using Xunit;

namespace LibOQS.NET.Tests;

/// <summary>
/// Regression tests for native interop lifetime and argument-validation defects.
/// </summary>
public class InteropSafetyTests
{
    // Before the SafeHandle migration, Dispose() checked and cleared its state without
    // synchronisation, so two threads could both reach OQS_KEM_free with the same pointer.
    // That aborted the process with a libmalloc "pointer being freed was not allocated" report.
    [Fact]
    public void ConcurrentDispose_ShouldNotDoubleFree()
    {
        for (var round = 0; round < 250; round++)
        {
            var kem = new KemInstance(KemAlgorithm.MlKem512);
            var sig = new SigInstance(SigAlgorithm.MlDsa44);

            using var gate = new ManualResetEventSlim(false);
            var threads = new[]
            {
                new Thread(() => { gate.Wait(); kem.Dispose(); }),
                new Thread(() => { gate.Wait(); kem.Dispose(); }),
                new Thread(() => { gate.Wait(); sig.Dispose(); }),
                new Thread(() => { gate.Wait(); sig.Dispose(); }),
            };

            foreach (var t in threads)
            {
                t.Start();
            }

            gate.Set();

            foreach (var t in threads)
            {
                Assert.True(t.Join(TimeSpan.FromSeconds(30)), "Dispose thread did not finish");
            }
        }
    }

    // The safe handle is reference-counted across the P/Invoke, so a Dispose() arriving from
    // another thread while a native call is in flight must not free the OQS_KEM underneath it.
    [Fact]
    public void DisposeDuringNativeCall_ShouldNotUseAfterFree()
    {
        for (var round = 0; round < 50; round++)
        {
            var kem = new KemInstance(KemAlgorithm.MlKem768);
            var disposer = new Thread(() => kem.Dispose());
            disposer.Start();

            try
            {
                var (publicKey, _) = kem.GenerateKeypair();
                Assert.Equal(kem.PublicKeyLength, publicKey.Length);
            }
            catch (ObjectDisposedException)
            {
                // Disposed before the call started: rejected cleanly, which is also correct.
            }

            Assert.True(disposer.Join(TimeSpan.FromSeconds(30)), "Dispose thread did not finish");
        }
    }

    // Instances that go out of scope without Dispose() are released by the handle's critical
    // finalizer. Exercise that under GC pressure to catch premature or double release.
    [Fact]
    public void UndisposedInstances_ShouldBeReleasedByFinalizer()
    {
        static int UseUnrootedKem() =>
            new KemInstance(KemAlgorithm.MlKem512).GenerateKeypair().PublicKey.Length;

        static int UseUnrootedSig() =>
            new SigInstance(SigAlgorithm.MlDsa44).GenerateKeypair().PublicKey.Length;

        for (var round = 0; round < 100; round++)
        {
            Assert.True(UseUnrootedKem() > 0);
            Assert.True(UseUnrootedSig() > 0);

            if (round % 10 == 0)
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
            }
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
    }

    // A zero-length seed used to slip past the `seed.Length != SeedLength` guard (0 != 0 is false)
    // and take the derandomized path with a NULL seed pointer, surfacing as a misleading
    // "Failed to encapsulate". It must be rejected up front instead.
    [SkippableFact]
    public void ZeroLengthSeed_OnAlgorithmWithoutDerandomization_ShouldThrowArgumentException()
    {
        Skip.If(!KemAlgorithm.ClassicMcEliece348864.IsEnabled(),
            "Classic-McEliece-348864 is not enabled in this build.");

        using var kem = new KemInstance(KemAlgorithm.ClassicMcEliece348864);
        Assert.False(kem.SupportsDerandomizedKeypair);
        Assert.False(kem.SupportsDerandomizedEncapsulation);

        var (publicKey, _) = kem.GenerateKeypair();

        var keypairEx = Assert.Throws<ArgumentException>(
            () => kem.GenerateKeypair(Array.Empty<byte>()));
        Assert.Equal("seed", keypairEx.ParamName);

        var encapsEx = Assert.Throws<ArgumentException>(
            () => kem.Encapsulate(publicKey, Array.Empty<byte>()));
        Assert.Equal("seed", encapsEx.ParamName);
    }

    [Fact]
    public void DerandomizationSupportFlags_ShouldMatchSeedLengths()
    {
        using var mlKem = new KemInstance(KemAlgorithm.MlKem512);
        Assert.True(mlKem.KeypairSeedLength > 0);
        Assert.True(mlKem.SupportsDerandomizedKeypair);
        Assert.True(mlKem.EncapsSeedLength > 0);
        Assert.True(mlKem.SupportsDerandomizedEncapsulation);
    }

    // OQS_SIG_supports_ctx_str returns a 1-byte C bool; the default P/Invoke return marshalling is
    // a 4-byte Win32 BOOL. Cross-check the raw binding against the instance property.
    [SkippableTheory]
    [InlineData(SigAlgorithm.MlDsa44)]
    [InlineData(SigAlgorithm.Falcon512)]
    public void SupportsContextString_ShouldAgreeWithNativeQuery(SigAlgorithm algorithm)
    {
        Skip.If(!algorithm.IsEnabled(), $"Algorithm {algorithm} is not enabled in this build.");

        using var sig = new SigInstance(algorithm);
        var native = Native.Sig.OQS_SIG_supports_ctx_str(algorithm.GetIdentifier());
        Assert.Equal(native, sig.SupportsContextString);
    }

    // liboqs exports OQS_MEM_insecure_free, not OQS_MEM_free; the old declaration always threw
    // EntryPointNotFoundException.
    [Fact]
    public void MemoryHelpers_ShouldResolveTheirEntryPoints()
    {
        var ptr = Native.Common.OQS_MEM_malloc((UIntPtr)64);
        Assert.NotEqual(IntPtr.Zero, ptr);

        Native.Common.OQS_MEM_cleanse(ptr, (UIntPtr)64);
        Native.Common.OQS_MEM_insecure_free(ptr);

        var secure = Native.Common.OQS_MEM_malloc((UIntPtr)64);
        Assert.NotEqual(IntPtr.Zero, secure);
        Native.Common.OQS_MEM_secure_free(secure, (UIntPtr)64);
    }

    // Initialize() used to run from a static constructor, so a missing or wrong-architecture
    // native library surfaced as TypeInitializationException and poisoned the type permanently.
    // It is now an ordinary idempotent method.
    [Fact]
    public void Initialize_ShouldBeIdempotentAndRetryable()
    {
        LibOqs.Initialize();
        LibOqs.Initialize();
        Assert.True(LibOqs.IsInitialized);

        LibOqs.EnsureInitialized();
        Assert.True(LibOqs.IsInitialized);
    }
}
