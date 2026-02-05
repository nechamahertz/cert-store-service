using System.Runtime.InteropServices;
using System;

namespace CpAgent.Security;

public static class LinuxNativeInterop
{
    // Socket option constants
    private const int SOL_SOCKET = 1;
    private const int SO_PEERCRED = 17;

    public const int SIGTERM = 15;

    // Structure for peer process credentials
    [StructLayout(LayoutKind.Sequential)]
    public struct ucred
    {
        public uint pid;
        public uint uid;
        public uint gid;
    }

    // --- P/Invoke Declarations ---

    [DllImport("libc", SetLastError = true)]
    public static extern int chmod(string path, uint mode);

    [DllImport("libc", SetLastError = true)]
    public static extern int mount(
        string source,
        string target,
        string filesystemtype,
        ulong mountflags,
        string data);

    [DllImport("libc", SetLastError = true)]
    public static extern int umount(string target);

    [DllImport("libc", SetLastError = true)]
    private static extern int getsockopt(
        int sockfd,
        int level,
        int optname,
        ref ucred optval,
        ref int optlen);

    [DllImport("libc", SetLastError = true)]
    public static extern int kill(int pid, int sig);

    // --- Helper Methods ---

    /// <summary>
    /// Retrieves the credentials of the process connected to the socket (PID, UID, GID)
    /// </summary>
    public static ucred? GetPeerCredentials(int socketHandle)
    {
        var credentials = new ucred();
        int len = Marshal.SizeOf(typeof(ucred));

        int result = getsockopt(
            socketHandle,
            SOL_SOCKET,
            SO_PEERCRED,
            ref credentials,
            ref len);

        if (result == 0)
        {
            return credentials;
        }

        return null;
    }

    /// <summary>
    /// Creates a secure tmpfs mount (memory-only filesystem) with strict security options
    /// </summary>
    public static void CreateSecureTmpfs(string path, string size = "10M")
    {
        // MS_NOSUID | MS_NODEV | MS_NOEXEC (4 | 2 | 8 = 14)
        // Prevents executable files, device nodes, and privilege escalation
        ulong flags = 14;
        string data = $"size={size},mode=0700";

        int result = mount("tmpfs", path, "tmpfs", flags, data);
        if (result != 0)
        {
            int error = Marshal.GetLastPInvokeError();
            throw new Exception($"Failed to mount tmpfs at {path}. Error code: {error}");
        }
    }

    /// <summary>
    /// Sets file permissions (chmod)
    /// </summary>
    public static void SetFilePermissions(string path, uint mode)
    {
        int result = chmod(path, mode);
        if (result != 0)
        {
            int error = Marshal.GetLastPInvokeError();
            throw new Exception($"Failed to set permissions for {path}. Error code: {error}");
        }
    }
}