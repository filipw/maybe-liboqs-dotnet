# LibOQS.NET: .NET bindings for liboqs

**LibOQS.NET** provides .NET bindings for the [Open Quantum Safe](https://openquantumsafe.org/) [liboqs](https://github.com/open-quantum-safe/liboqs/) C library, which is a C library for quantum-resistant cryptographic algorithms.

This project offers two .NET packages:

- The `LibOQS.NET.Native` package provides low-level P/Invoke bindings to the liboqs C library
- The `LibOQS.NET` package offers a high-level, type-safe .NET API for the quantum-resistant algorithms

## Getting Started

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

   ```powershell
   .\build-dotnet-liboqs.ps1
   ```

   This will:
   - Configure and build liboqs as a shared library
   - Copy the resulting `oqs.dll` to the appropriate directories
   - Enable common quantum-resistant algorithms (ML-KEM, ML-DSA, Kyber, Dilithium, Falcon, FrodoKEM)

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

5. **Create NuGet packages:**

   ```bash
   dotnet pack --configuration Release
   ```

### Submodule Management

This project uses [liboqs v0.13.0](https://github.com/Open-Quantum-Safe/liboqs/releases/tag/0.13.0) as a git submodule.

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

## Features

- **Key Encapsulation Mechanisms (KEMs)**: ML-KEM, Kyber, FrodoKEM, and more
- **Digital Signatures**: ML-DSA, Dilithium, Falcon, SPHINCS+, and more
- **Type-safe API**: Strong typing with enums for algorithms and proper resource management
- **Memory management**: Automatic cleanup of native resources using IDisposable pattern
- **Cross-platform**: Supports Windows, Linux, and macOS on x64 and ARM64
- **Automatic initialization**: LibOQS initializes automatically when first accessed

## Quick Start

### Installation

```xml
<PackageReference Include="LibOQS.NET" Version="0.11.0" />
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

## Project Structure

```
├── build-dotnet-liboqs.ps1     # Build script for native liboqs library
├── LibOQS.NET.sln              # Visual Studio solution file
├── liboqs/                     # Git submodule - liboqs C library v0.13.0
├── src/
│   ├── LibOQS.NET/            # High-level .NET API
│   ├── LibOQS.NET.Native/     # Low-level P/Invoke bindings
│   ├── LibOQS.NET.Tests/      # Unit tests
│   ├── Examples/              # Usage examples
│   └── native/                # Built native libraries (oqs.dll)
└── README.md                  # This file
```

## Supported Algorithms

### Key Encapsulation Mechanisms (KEMs)

- **ML-KEM** (NIST standardized): ML-KEM-512, ML-KEM-768, ML-KEM-1024
- **Kyber**: Kyber512, Kyber768, Kyber1024
- **FrodoKEM**: FrodoKEM-640-AES, FrodoKEM-640-SHAKE, FrodoKEM-976-AES, FrodoKEM-976-SHAKE, FrodoKEM-1344-AES, FrodoKEM-1344-SHAKE

### Digital Signatures

- **ML-DSA** (NIST standardized): ML-DSA-44, ML-DSA-65, ML-DSA-87
- **Dilithium**: Dilithium2, Dilithium3, Dilithium5
- **Falcon**: Falcon-512, Falcon-1024
- **SPHINCS+**: Various parameter sets

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

## Platform-Specific Requirements

### Windows
- Ensure `oqs.dll` is in your PATH or in the application directory
- Built with Visual Studio Build Tools or equivalent

### Linux
- Ensure `liboqs.so` is in `/usr/lib`, `/usr/local/lib`, or another library path
- Built with GCC or Clang

### macOS
- Ensure `liboqs.dylib` is in the library path
- Built with Clang

## Troubleshooting

### DllNotFoundException
If you get a `DllNotFoundException`, it means the liboqs shared library cannot be found. Make sure:
1. You've run the build script: `.\build-dotnet-liboqs.ps1`
2. The library is built for your platform and architecture
3. The library is in your system's library search path
4. All dependencies of liboqs are available

### AlgorithmNotSupportedException
This means the algorithm you're trying to use was not enabled when liboqs was compiled. You can:
1. Check which algorithms are enabled using the `.IsEnabled()` method
2. Rebuild liboqs with the desired algorithms enabled
3. Use a different algorithm that is available

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
