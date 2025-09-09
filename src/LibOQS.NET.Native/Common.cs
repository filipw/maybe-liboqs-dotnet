using System.Runtime.InteropServices;

namespace LibOQS.NET.Native;

/// <summary>
/// Common structures and constants used by liboqs
/// </summary>
public static class Common
{
    /// <summary>
    /// Library name for P/Invoke calls
    /// </summary>
    public const string LibraryName = "oqs";

    /// <summary>
    /// OQS status codes
    /// </summary>
    public enum OqsStatus : int
    {
        /// <summary>
        /// Success
        /// </summary>
        Success = 0,
        
        /// <summary>
        /// Error
        /// </summary>
        Error = -1
    }

    /// <summary>
    /// Initialize the OQS library
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void OQS_init();

    /// <summary>
    /// Cleanup the OQS library
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void OQS_destroy();

    /// <summary>
    /// Get memory functions
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr OQS_MEM_malloc(UIntPtr size);

    /// <summary>
    /// Free memory
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void OQS_MEM_free(IntPtr ptr);

    /// <summary>
    /// Secure free memory
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void OQS_MEM_secure_free(IntPtr ptr, UIntPtr size);

    /// <summary>
    /// Clear memory
    /// </summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void OQS_MEM_cleanse(IntPtr ptr, UIntPtr size);
}
