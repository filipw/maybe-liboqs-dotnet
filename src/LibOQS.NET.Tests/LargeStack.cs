using System.Runtime.ExceptionServices;

namespace LibOQS.NET.Tests;

/// <summary>
/// Runs a test body on a thread with enough stack for the most demanding liboqs algorithms.
/// </summary>
/// <remarks>
/// Several algorithms - notably in the SNOVA, Classic McEliece, CROSS and MAYO families - need
/// considerably more stack than a default thread provides, and a stack overflow is fail-fast in
/// .NET: it kills the test host rather than failing a single test. The exact requirement varies by
/// algorithm, platform and CPU architecture, since liboqs compiles a different implementation per
/// architecture, so this simply reserves an amount well above anything observed so far.
///
/// Running tests here means they measure the algorithm rather than the ambient stack size of
/// whatever thread xUnit happened to pick.
/// </remarks>
internal static class LargeStack
{
    /// <summary>
    /// Reserved address space, not committed memory, so this can be generous.
    /// </summary>
    private const int StackBytes = 16 * 1024 * 1024;

    public static void Run(Action body)
    {
        ExceptionDispatchInfo? failure = null;

        var thread = new Thread(() =>
        {
            try
            {
                body();
            }
            catch (Exception ex)
            {
                // Captured and rethrown on the calling thread so xUnit sees assertion failures
                // and Skip exceptions exactly as it would without the extra thread.
                failure = ExceptionDispatchInfo.Capture(ex);
            }
        }, StackBytes);

        thread.Start();
        thread.Join();

        failure?.Throw();
    }
}
