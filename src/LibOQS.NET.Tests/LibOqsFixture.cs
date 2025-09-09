using LibOQS.NET;

namespace LibOQS.NET.Tests;

/// <summary>
/// Test fixture to ensure LibOQS is properly managed for all tests
/// </summary>
public class LibOqsFixture : IDisposable
{
    public LibOqsFixture()
    {
        // LibOQS initialization is automatic via static constructor
        LibOqs.EnsureInitialized();
    }

    public void Dispose()
    {
        // Cleanup when all tests are done
        LibOqs.Cleanup();
    }
}
