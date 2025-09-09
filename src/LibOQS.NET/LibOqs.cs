namespace LibOQS.NET;

/// <summary>
/// Exception thrown when an OQS operation fails
/// </summary>
public class OqsException : Exception
{
    public OqsException(string message) : base(message) { }
    public OqsException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Exception thrown when an algorithm is not supported or not enabled
/// </summary>
public class AlgorithmNotSupportedException : OqsException
{
    public AlgorithmNotSupportedException(string algorithm) 
        : base($"Algorithm '{algorithm}' is not supported or not enabled") { }
}

/// <summary>
/// Main library initialization and management
/// </summary>
public static class LibOqs
{
    private static bool _initialized = false;
    private static readonly object _initLock = new object();

    /// <summary>
    /// Static constructor to automatically initialize LibOQS when first accessed
    /// </summary>
    static LibOqs()
    {
        Initialize();
    }

    /// <summary>
    /// Initialize the OQS library. This should be called before using any other OQS functions.
    /// </summary>
    public static void Initialize()
    {
        lock (_initLock)
        {
            if (!_initialized)
            {
                try
                {
                    Native.Common.OQS_init();
                    _initialized = true;
                }
                catch (DllNotFoundException ex)
                {
                    throw new OqsException(
                        "Unable to load the liboqs shared library. " +
                        "Please ensure that oqs.dll (Windows), liboqs.so (Linux), or liboqs.dylib (macOS) " +
                        "is available in your system's library path or in the application directory. " +
                        "See BUILD.md for installation instructions.", ex);
                }
            }
        }
    }

    /// <summary>
    /// Cleanup the OQS library
    /// </summary>
    public static void Cleanup()
    {
        lock (_initLock)
        {
            if (_initialized)
            {
                Native.Common.OQS_destroy();
                _initialized = false;
            }
        }
    }

    /// <summary>
    /// Check if the library has been initialized
    /// </summary>
    public static bool IsInitialized => _initialized;

    /// <summary>
    /// Ensure the library is initialized, automatically initializing if needed
    /// </summary>
    public static void EnsureInitialized()
    {
        if (!_initialized)
        {
            Initialize();
        }
    }
}
