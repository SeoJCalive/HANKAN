using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

public static class HankanProcessJob
{
    [StructLayout(LayoutKind.Sequential)]
    struct BasicLimits
    {
        public long ProcessTime, JobTime;
        public uint Flags;
        public UIntPtr MinWorkingSet, MaxWorkingSet;
        public uint ActiveProcesses;
        public UIntPtr Affinity;
        public uint Priority, Scheduling;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct IoCounters
    {
        public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct ExtendedLimits
    {
        public BasicLimits Basic;
        public IoCounters Io;
        public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetInformationJobObject(IntPtr job, int kind,
        ref ExtendedLimits limits, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);
    static IntPtr job;

    public static void Attach()
    {
        job = CreateJobObject(IntPtr.Zero, String.Empty);
        if (job == IntPtr.Zero) throw new Win32Exception();
        var limits = new ExtendedLimits();
        limits.Basic.Flags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if (!SetInformationJobObject(job, 9, ref limits,
                (uint)Marshal.SizeOf(typeof(ExtendedLimits))) ||
            !AssignProcessToJobObject(job, Process.GetCurrentProcess().Handle))
        {
            int error = Marshal.GetLastWin32Error();
            CloseHandle(job);
            throw new Win32Exception(error);
        }
    }
}

// Windows PowerShell output callbacks cannot depend on a PowerShell runspace.
public sealed class HankanChild : IDisposable
{
    public Process Process { get; private set; }
    public volatile bool Connected;
    public volatile bool OutputFailed;
    public volatile string QuickUrl = "";
    readonly object outputLock = new object();
    readonly string logPath;
    readonly string kind;
    string token;

    public HankanChild(ProcessStartInfo info, string logPath, string kind, string token)
    {
        this.logPath = logPath;
        this.kind = kind;
        this.token = token;
        info.UseShellExecute = false;
        info.CreateNoWindow = true;
        info.RedirectStandardOutput = true;
        info.RedirectStandardError = true;
        Process = new Process { StartInfo = info };
        Process.OutputDataReceived += OnOutput;
        Process.ErrorDataReceived += OnOutput;
        if (!Process.Start()) throw new InvalidOperationException("Child did not start.");
        // The child has its own environment copy. Do not keep another in StartInfo.
        info.EnvironmentVariables.Remove("TUNNEL_TOKEN");
        Process.BeginOutputReadLine();
        Process.BeginErrorReadLine();
    }

    public static string AllowedTunnelLine(string line, string token, bool quick)
    {
        if (!String.IsNullOrEmpty(token)) line = line.Replace(token, "[removed]");
        if (Regex.IsMatch(line, "Registered tunnel connection.*protocol=http2"))
            return "tunnel connection ready";
        if (quick)
        {
            var match = Regex.Match(line, @"https://[a-z0-9-]+\.trycloudflare\.com");
            if (match.Success) return match.Value;
        }
        // No raw exception, debug, credentials, headers, or environment output.
        return "";
    }

    void OnOutput(object sender, DataReceivedEventArgs args)
    {
        if (args.Data == null) return;
        lock (outputLock)
        {
            var line = kind == "server" ? args.Data : AllowedTunnelLine(args.Data, token, kind == "quick");
            if (line.Length == 0) return;
            if (kind != "server")
            {
                if (line == "tunnel connection ready") Connected = true;
                else QuickUrl = line;
            }
            try { File.AppendAllText(logPath, line + Environment.NewLine); }
            catch (IOException) { OutputFailed = true; }
            catch (UnauthorizedAccessException) { OutputFailed = true; }
        }
    }

    public static string Probe(ProcessStartInfo info)
    {
        info.UseShellExecute = false;
        info.CreateNoWindow = true;
        info.RedirectStandardOutput = true;
        info.RedirectStandardError = true;
        using (var process = Process.Start(info))
        {
            if (process == null) throw new InvalidOperationException("Probe did not start.");
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(10000))
            {
                process.Kill();
                process.WaitForExit();
                throw new InvalidOperationException("Probe timeout.");
            }
            System.Threading.Tasks.Task.WaitAll(output, error);
            if (process.ExitCode != 0) throw new InvalidOperationException("Probe failed.");
            return output.Result + error.Result;
        }
    }

    public void Dispose()
    {
        if (!Process.HasExited) Process.Kill();
        Process.WaitForExit();
        Process.Dispose();
        token = "";
    }
}
