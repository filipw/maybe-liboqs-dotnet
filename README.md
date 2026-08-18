# Maybe LibOQS.NET: .NET library for liboqs

**LibOQS.NET** provides .NET wrapper/bindings for the [Open Quantum Safe](https://openquantumsafe.org/) [liboqs](https://github.com/open-quantum-safe/liboqs/) C library, which is a C library for quantum-resistant cryptographic algorithms.

This project offers two .NET packages:

- The `LibOQS.NET.Native` package provides low-level P/Invoke bindings to the liboqs C library
- The `LibOQS.NET` package offers a high-level, type-safe .NET API for the quantum-resistant algorithms

Both packages are **self-contained** and include all necessary native dependencies - no manual compilation or native library installation is required.

## Quick Start

### Installation

Install from NuGet - no additional dependencies or native compilation required:

```xml
<PackageReference Include="LibOQS.NET" Version="...version..." />
```

Or via the .NET CLI:

```bash
dotnet add package LibOQS.NET
```

### Basic Usage

```csharp
using LibOQS.NET;

// LibOQS initializes on first use - no manual Initialize() call needed
try
{
    // Key Encapsulation Mechanism example
    using var kem = new KemInstance(KemAlgorithm.MlKem512);
    
    // Generate keypair
    var (publicKey, secretKey) = kem.GenerateKeypair();
    
    // Encapsulate a shared secret
    var (ciphertext, sharedSecret1) = kem.Encapsulate(publicKey);
    
    // Decapsulate the shared secret
    var sharedSecret2 = kem.Decapsulate(secretKey, ciphertext);
    
    // Verify they match
    Console.WriteLine($"Shared secrets match: {sharedSecret1.SequenceEqual(sharedSecret2)}");
    
    // Digital signature example
    using var sig = new SigInstance(SigAlgorithm.MlDsa44);
    
    // Generate signature keypair
    var (sigPublicKey, sigSecretKey) = sig.GenerateKeypair();
    
    // Sign a message
    var message = System.Text.Encoding.UTF8.GetBytes("Hello, post-quantum world!");
    var signature = sig.Sign(message, sigSecretKey);
    
    // Verify the signature
    var isValid = sig.Verify(message, signature, sigPublicKey);
    Console.WriteLine($"Signature valid: {isValid}");
}
finally
{
    // Optional: releases OQS_destroy() state. Only safe once every instance above is disposed,
    // which the `using` declarations guarantee by the time we get here.
    LibOqs.Cleanup();
}
```

### Signed Key Exchange Example

```csharp
using LibOQS.NET;

try
{
    using var sigAlg = new SigInstance(SigAlgorithm.MlDsa44);
    using var kemAlg = new KemInstance(KemAlgorithm.MlKem512);
    
    // A's long-term secrets
    var (aSigPk, aSigSk) = sigAlg.GenerateKeypair();
    // B's long-term secrets  
    var (bSigPk, bSigSk) = sigAlg.GenerateKeypair();

    // A -> B: kem_pk, signature
    var (kemPk, kemSk) = kemAlg.GenerateKeypair();
    var signature1 = sigAlg.Sign(kemPk, aSigSk);

    // B -> A: kem_ct, signature
    if (!sigAlg.Verify(kemPk, signature1, aSigPk))
        throw new Exception("Failed to verify A's signature");
        
    var (kemCt, bKemSs) = kemAlg.Encapsulate(kemPk);
    var signature2 = sigAlg.Sign(kemCt, bSigSk);

    // A verifies, decapsulates, now both have kem_ss
    if (!sigAlg.Verify(kemCt, signature2, bSigPk))
        throw new Exception("Failed to verify B's signature");
        
    var aKemSs = kemAlg.Decapsulate(kemSk, kemCt);
    
    // Verify shared secrets match
    if (aKemSs.SequenceEqual(bKemSs))
        Console.WriteLine("Key exchange successful!");
}
finally
{
    LibOqs.Cleanup();
}
```

## Features

- **Key Encapsulation Mechanisms (KEMs)**: ML-KEM, Kyber, BIKE, HQC, NTRU, Classic McEliece, NTRU Prime, FrodoKEM (standard/salted and ephemeral eFrodoKEM)
- **Digital Signatures**: ML-DSA, SLH-DSA, Falcon, MAYO, CROSS, UOV, SNOVA, MQOM
- **New Features**: Support for context strings in signatures and derandomized (deterministic) operations in KEM.
- **Type-safe API**: Strong typing with enums for algorithms and proper resource management
- **Memory management**: Automatic cleanup of native resources using IDisposable pattern
- **Cross-platform**: Supports Windows x64/ARM64, macOS ARM64, and Linux x64/ARM64 on both glibc and musl (Alpine)
- **Targets**: .NET 10 and .NET 9, so usable from .NET 9.0 or later
- **Self-contained**: No manual native library installation or compilation required

## Supported Algorithms

### Key Encapsulation Mechanisms (KEMs)

- **ML-KEM** (NIST standardized): ML-KEM-512, ML-KEM-768, ML-KEM-1024
- **Kyber**: Kyber512, Kyber768, Kyber1024
- **BIKE**: BIKE-L1, BIKE-L3, BIKE-L5
- **HQC**: HQC-1, HQC-3, HQC-5
- **NTRU**: NTRU-HPS-2048-509, NTRU-HPS-2048-677, NTRU-HPS-4096-821, NTRU-HPS-4096-1229, NTRU-HRSS-701, NTRU-HRSS-1373
- **Classic McEliece**: All 10 variants (e.g., 348864, 460896, 6688128, 6960119, 8192128 with fast variants)
- **NTRU Prime**: sntrup761
- **FrodoKEM** (standard, salted variant): FrodoKEM-640-AES, FrodoKEM-640-SHAKE, FrodoKEM-976-AES, FrodoKEM-976-SHAKE, FrodoKEM-1344-AES, FrodoKEM-1344-SHAKE
- **eFrodoKEM** (ephemeral variant): eFrodoKEM-640-AES, eFrodoKEM-640-SHAKE, eFrodoKEM-976-AES, eFrodoKEM-976-SHAKE, eFrodoKEM-1344-AES, eFrodoKEM-1344-SHAKE

### Digital Signatures

- **ML-DSA** (NIST standardized): ML-DSA-44, ML-DSA-65, ML-DSA-87
- **SLH-DSA** (NIST standardized): All 12 pure variants (SHA2 and SHAKE, 128/192/256, fast/small)
- **Falcon**: Falcon-512, Falcon-1024, Falcon-Padded-512, Falcon-Padded-1024
- **MAYO**: MAYO-1, MAYO-2, MAYO-3, MAYO-5
- **CROSS**: All 18 variants (RSDP/RSDPG, Balanced/Fast/Small)
- **UOV**: All 12 variants (Ip, Is, III, V; with pkc/skc variants)
- **SNOVA**: All 12 variants
- **MQOM**: All 12 variants (mqom2_cat1/3/5_gf16_fast/short_r3/r5)

## Algorithm Availability

Not all algorithms may be available in every build of liboqs. You can check if an algorithm is enabled:

```csharp
if (KemAlgorithm.MlKem512.IsEnabled())
{
    // Use ML-KEM-512
    using var kem = new KemInstance(KemAlgorithm.MlKem512);
    // ...
}
```

## Memory Management

Native resources are held behind a `SafeHandle`:

- **Automatic initialization**: the native library is initialized on demand by the first call that needs it; you never have to call `LibOqs.Initialize()` yourself, though it is public and idempotent
- **Deterministic release**: wrap `KemInstance` and `SigInstance` in `using` declarations. `Dispose()` is idempotent and safe to call concurrently
- **Backstop**: an instance that is never disposed is released by the handle's critical finalizer, so the native allocation is not leaked
- **Optional manual cleanup**: `LibOqs.Cleanup()` calls `OQS_destroy()`. Only call it once every instance has been disposed — liboqs behaviour is undefined if instances outlive it. It is *not* invoked automatically at process exit

> [!IMPORTANT]
> Key material is returned as ordinary managed `byte[]`. The garbage collector may move or copy
> those arrays, and nothing zeroes them when they fall out of scope, so the library cannot
> guarantee that secret keys or shared secrets are erased from process memory. If that matters for
> your threat model, clear the arrays yourself when you are done with them (for example with
> `CryptographicOperations.ZeroMemory`) and consider pinning them for their lifetime.

## Stack Requirements

Some parameter sets - notably in the SNOVA, Classic McEliece, CROSS and MAYO families - need
considerably more stack than a default .NET thread provides. This matters because a stack overflow
is fail-fast in .NET: it terminates the process and cannot be caught.

If you use one of those families and see the process die without an exception, run the work on a
thread you size yourself:

```csharp
// 16 MB of reserved address space, not committed memory
var thread = new Thread(() =>
{
    using var sig = new SigInstance(SigAlgorithm.Snova60_10_4);
    var (publicKey, secretKey) = sig.GenerateKeypair();
    // ...
}, 16 * 1024 * 1024);

thread.Start();
thread.Join();
```

The exact requirement varies by algorithm, platform and CPU architecture, because liboqs compiles
a different implementation per architecture. It has not been characterised across all supported
platforms yet, so no per-algorithm figures are published here.

> [!NOTE]
> This is also why the package targets .NET 9.0 as its floor: on .NET 8 a non-main thread receives
> only the 512 KB macOS default, which is too small for several of these algorithms. .NET 9 raised
> it.

## Thread Safety

- The on-demand initialization is thread-safe
- `Dispose()` is thread-safe and idempotent on both `KemInstance` and `SigInstance`, and will not release the native object while another thread still has a call in flight
- Prefer a separate `KemInstance` / `SigInstance` per thread. The instances hold no mutable managed state, but sharing one across threads is not covered by the test suite
- Call `LibOqs.Cleanup()` once at application shutdown, if at all, and only after every instance has been disposed

## Error Handling

The library throws specific exceptions:

- `OqsException`: General OQS operation failures
- `AlgorithmNotSupportedException`: When an algorithm is not enabled
- `ArgumentException`: Invalid parameters
- `ObjectDisposedException`: Using disposed objects

## Building from Source (For Development)

The NuGet packages are self-contained and don't require building from source. This section is only for developers who want to contribute or modify the library.

### Prerequisites

- **.NET 10.0 SDK** (pinned by `global.json`)
- **CMake** 3.5 or later
- **C/C++ compiler** (Visual Studio Build Tools on Windows, GCC/Clang on Linux/macOS)
- **Git** with submodule support

### Clone with Submodules

This repository uses git submodules to include the liboqs library. Clone with submodules:

```bash
git clone --recursive https://github.com/filipw/maybe-liboqs-dotnet.git
cd maybe-liboqs-dotnet
```

If you already cloned without `--recursive`, initialize the submodules:

```bash
git submodule init
git submodule update
```

### Building

1. **Build the native liboqs library:**

    On Windows, run the PowerShell script:
   ```powershell
   .\build-dotnet-liboqs.ps1
   ```

    On Linux, run the bash script:
    ```bash
    ./build-dotnet-liboqs-linux.sh
    ``` 

    On Mac, use:
    ```bash
    ./build-dotnet-liboqs-macos.sh
    ```

   This will:
   - Configure and build liboqs as a shared library
   - Copy the resulting DLL/so/dylib to the appropriate directories
   - Enable all common quantum-resistant algorithms (ML-KEM, ML-DSA, SLH-DSA, Kyber, Falcon, FrodoKEM, BIKE, HQC, NTRU, SNOVA, MQOM, etc.)
   - On Windows and macOS, build MQOM from its memory-optimized implementation (`-DOQS_MEMOPT_BUILD=ON`), see [Platform Support](#platform-support)

2. **Build the .NET libraries:**

   ```bash
   dotnet build
   ```

3. **Run tests:**

   ```bash
   dotnet test
   ```

4. **Run examples:**

   ```bash
   cd src/Examples
   dotnet run
   ```

### Submodule Management

This project uses [liboqs 0.16.0](https://github.com/Open-Quantum-Safe/liboqs/releases/tag/0.16.0) as a git submodule.

**Update to latest liboqs version:**
```bash
cd liboqs
git fetch
git checkout <new-tag>
cd ..
git add liboqs
git commit -m "Update liboqs to <new-tag>"
```

**Working with submodules:**
```bash
# Initialize submodules after cloning
git submodule init
git submodule update

# Update all submodules to latest commits
git submodule update --remote

# Clone with all submodules
git clone --recursive <repo-url>
```

## Platform Support

LibOQS.NET supports the following platforms out of the box with no additional setup required:

- **Windows x64**
- **Windows ARM64** 
- **Linux x64** (glibc)
- **Linux ARM64** (glibc)
- **Linux x64 musl** (Alpine)
- **Linux ARM64 musl** (Alpine)
- **macOS ARM64**

> [!NOTE]
> **Platform Limitations**:
> - **Windows**: `SLH-DSA` (Pure variants) is disabled because of a known bug in `liboqs` that causes a stack overflow during signing on Windows. `BIKE` is unavailable because `liboqs` itself does not support it on Windows.
> - **MQOM** is enabled on all platforms. On Windows and macOS it is built from the memory-optimized implementation introduced in `liboqs` 0.16.0 (`OQS_MEMOPT_BUILD`), because the default implementation needs more than 1 MB of stack to sign and overflows the stack of non-main threads. Linux keeps the default (AVX2-accelerated on x64) implementation, where the larger default thread stack is sufficient.

The NuGet packages include all necessary native libraries for these platforms.

## Troubleshooting

### AlgorithmNotSupportedException
This means the algorithm you're trying to use was not enabled when liboqs was compiled. You can:
1. Check which algorithms are enabled using the `.IsEnabled()` method
2. Use a different algorithm that is available

### DllNotFoundException / "Error loading shared library liboqs"
The native library ships per runtime identifier. If loading fails, check that the RID your app
resolves to has a matching asset in the package. A distinctive case is musl-based distributions
such as Alpine, where a glibc build fails with a message naming the glibc loader:

```
Error loading shared library ld-linux-x86-64.so.2: No such file or directory (needed by .../liboqs.so)
```

That means a `linux-x64` (glibc) asset was picked on a musl system. The package carries separate
`linux-musl-x64` and `linux-musl-arm64` assets for this; make sure you are on a version that
includes them.

### General Issues
If you encounter issues:
1. Ensure you're using a supported platform (see Platform Support above)
2. Check that your .NET runtime version is compatible (.NET 9.0 or later)
3. Verify the algorithm you're trying to use is enabled with `.IsEnabled()`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Ensure tests pass: `dotnet test`
5. Submit a pull request

When working with submodules:
- Keep liboqs submodule updates in separate commits
- Test thoroughly after submodule updates
- Update documentation if API changes occur

## Security Considerations

⚠️ **Important**: This library is intended for prototyping and evaluation purposes. The quantum-resistant algorithms are still under standardization and may change. For production use, consider hybrid approaches that combine post-quantum algorithms with traditional cryptography.

## License

LibOQS.NET is licensed under the MIT license.

The included liboqs library is covered by its own [license](https://github.com/open-quantum-safe/liboqs/blob/main/LICENSE.txt).

## Acknowledgments

- [Open Quantum Safe](https://openquantumsafe.org/) project
- [liboqs](https://github.com/open-quantum-safe/liboqs/) C library
- The quantum cryptography research community
