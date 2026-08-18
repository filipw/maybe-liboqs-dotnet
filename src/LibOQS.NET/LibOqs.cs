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
    private static volatile bool _initialized;
    private static readonly object _initLock = new object();

    /// <summary>
    /// Initialize the OQS library. Calling this is optional: every entry point that needs the
    /// native library initializes it on demand. Safe to call repeatedly and from multiple threads.
    /// </summary>
    public static void Initialize()
    {
        if (_initialized)
        {
            return;
        }

        lock (_initLock)
        {
            if (_initialized)
            {
                return;
            }

            try
            {
                Native.Common.OQS_init();
            }
            catch (Exception ex) when (ex is DllNotFoundException
                                    || ex is BadImageFormatException
                                    || ex is EntryPointNotFoundException)
            {
                throw new OqsException(
                    "Unable to load the liboqs native library. Ensure that oqs.dll (Windows), " +
                    "liboqs.so (Linux) or liboqs.dylib (macOS) built for this process architecture " +
                    "is present in the application directory or on the platform's library search " +
                    "path. See the \"Building from Source\" section of README.md.", ex);
            }

            _initialized = true;
        }
    }

    /// <summary>
    /// Cleanup the OQS library.
    /// </summary>
    /// <remarks>
    /// Only call this once every <see cref="KemInstance"/> and <see cref="SigInstance"/> has been
    /// disposed; liboqs behaviour is undefined if instances outlive <c>OQS_destroy</c>. This is not
    /// invoked automatically at process exit.
    /// </remarks>
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
    public static void EnsureInitialized() => Initialize();
}
