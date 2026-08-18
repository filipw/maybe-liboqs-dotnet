using System.Runtime.InteropServices;

namespace LibOQS.NET.Native;

/// <summary>
/// Safe handle for an <c>OQS_KEM</c> allocated by <see cref="Kem.OQS_KEM_new_handle"/>.
/// </summary>
/// <remarks>
/// Passing this handle to a P/Invoke keeps it alive and reference-counted for the duration of the
/// call, so the underlying <c>OQS_KEM</c> cannot be released while native code is still using it.
/// Releasing is idempotent and thread-safe, which rules out double frees.
/// </remarks>
public sealed class OqsKemHandle : SafeHandle
{
    // Required by the interop marshaller, which instantiates the handle when a
    // P/Invoke declared with this return type returns.
    private OqsKemHandle() : base(IntPtr.Zero, ownsHandle: true) { }

    /// <inheritdoc />
    public override bool IsInvalid => handle == IntPtr.Zero;

    /// <inheritdoc />
    protected override bool ReleaseHandle()
    {
        Kem.OQS_KEM_free(handle);
        return true;
    }
}

/// <summary>
/// Safe handle for an <c>OQS_SIG</c> allocated by <see cref="Sig.OQS_SIG_new_handle"/>.
/// </summary>
/// <remarks>
/// Passing this handle to a P/Invoke keeps it alive and reference-counted for the duration of the
/// call, so the underlying <c>OQS_SIG</c> cannot be released while native code is still using it.
/// Releasing is idempotent and thread-safe, which rules out double frees.
/// </remarks>
public sealed class OqsSigHandle : SafeHandle
{
    // Required by the interop marshaller, which instantiates the handle when a
    // P/Invoke declared with this return type returns.
    private OqsSigHandle() : base(IntPtr.Zero, ownsHandle: true) { }

    /// <inheritdoc />
    public override bool IsInvalid => handle == IntPtr.Zero;

    /// <inheritdoc />
    protected override bool ReleaseHandle()
    {
        Sig.OQS_SIG_free(handle);
        return true;
    }
}
