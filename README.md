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

// LibOQS initializes automatically - no manual Initialize() call needed
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
    // Optional cleanup - called automatically at app shutdown
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

- **Key Encapsulation Mechanisms (KEMs)**: ML-KEM, Kyber, BIKE, HQC, NTRU, Classic McEliece, NTRU Prime, FrodoKEM
- **Digital Signatures**: ML-DSA, SLH-DSA, Falcon, SPHINCS+, MAYO, CROSS, UOV, SNOVA
- **New Features**: Support for context strings in signatures and derandomized (deterministic) operations in KEM.
- **Type-safe API**: Strong typing with enums for algorithms and proper resource management
- **Memory management**: Automatic cleanup of native resources using IDisposable pattern
- **Cross-platform**: Supports Windows x64, Windows ARM64, macOS ARM64, Linux x64, and Linux ARM64
- **Self-contained**: No manual native library installation or compilation required

## Supported Algorithms

### Key Encapsulation Mechanisms (KEMs)

- **ML-KEM** (NIST standardized): ML-KEM-512, ML-KEM-768, ML-KEM-1024
- **Kyber**: Kyber512, Kyber768, Kyber1024
- **BIKE**: BIKE-L1, BIKE-L3, BIKE-L5
- **HQC**: HQC-128, HQC-192, HQC-256
- **NTRU**: NTRU-HPS-2048-509, NTRU-HPS-2048-677, NTRU-HPS-4096-821, NTRU-HPS-4096-1229, NTRU-HRSS-701, NTRU-HRSS-1373
- **Classic McEliece**: All 10 variants (e.g., 348864, 460896, 6688128, 6960119, 8192128 with fast variants)
- **NTRU Prime**: sntrup761
- **FrodoKEM**: FrodoKEM-640-AES, FrodoKEM-640-SHAKE, FrodoKEM-976-AES, FrodoKEM-976-SHAKE, FrodoKEM-1344-AES, FrodoKEM-1344-SHAKE

### Digital Signatures

- **ML-DSA** (NIST standardized): ML-DSA-44, ML-DSA-65, ML-DSA-87
- **SLH-DSA** (NIST standardized): All 12 pure variants (SHA2 and SHAKE, 128/192/256, fast/small)
- **Falcon**: Falcon-512, Falcon-1024, Falcon-Padded-512, Falcon-Padded-1024
- **SPHINCS+**: All "simple" variants (SHA2 and SHAKE, 128/192/256, fast/small)
- **MAYO**: MAYO-1, MAYO-2, MAYO-3, MAYO-5
- **CROSS**: All 18 variants (RSDP/RSDPG, Balanced/Fast/Small)
- **UOV**: All 12 variants (Ip, Is, III, V; with pkc/skc variants)
- **SNOVA**: All 12 variants

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

The library properly manages native resources:

- **Automatic initialization**: LibOQS initializes automatically via static constructor
- **Automatic cleanup**: Use `using` statements with `KemInstance` and `SigInstance`
- **Optional manual cleanup**: Call `LibOqs.Cleanup()` when completely done with the library

## Thread Safety

The native liboqs library is generally thread-safe for read operations but may not be thread-safe for initialization. It's recommended to:

- Use separate instances of `KemInstance` and `SigInstance` per thread
- The automatic initialization is thread-safe
- Call `LibOqs.Cleanup()` once at application shutdown if needed

## Error Handling

The library throws specific exceptions:

- `OqsException`: General OQS operation failures
- `AlgorithmNotSupportedException`: When an algorithm is not enabled
- `ArgumentException`: Invalid parameters
- `ObjectDisposedException`: Using disposed objects

## Building from Source (For Development)

The NuGet packages are self-contained and don't require building from source. This section is only for developers who want to contribute or modify the library.

### Prerequisites

- **.NET 9.0 SDK** or later
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
   - Enable all common quantum-resistant algorithms (ML-KEM, ML-DSA, SLH-DSA, Kyber, Falcon, FrodoKEM, BIKE, HQC, SPHINCS+, NTRU, SNOVA, etc.)

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

This project uses [liboqs v0.15.0](https://github.com/Open-Quantum-Safe/liboqs/releases/tag/0.15.0) as a git submodule.

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
- **Linux x64**
- **Linux ARM64**
- **macOS ARM64**

The NuGet packages include all necessary native libraries for these platforms.

## Troubleshooting

### AlgorithmNotSupportedException
This means the algorithm you're trying to use was not enabled when liboqs was compiled. You can:
1. Check which algorithms are enabled using the `.IsEnabled()` method
2. Use a different algorithm that is available

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
