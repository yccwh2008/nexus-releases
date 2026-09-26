# 仅供公开分发仓库的标准 Windows Actions；无参数、无本机绕过开关。
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$site = 'https://yccwh2008.github.io/nexus-releases/'
$clock = [Diagnostics.Stopwatch]::StartNew()
$launches = [Collections.Generic.List[object]]::new()
$managedChildren = [Collections.Generic.List[object]]::new()
$cleanupFailed = $false
$report = [ordered]@{ schema = 1; result = 'failed'; phase = 'guard'; checks = @() }
$summaryAllowed = $false
$environmentSet = $false
$client = $null
$phaseStartedMs = -1

function Require([bool]$Condition, [string]$Code) {
    if (-not $Condition) { throw $Code }
}

function Initialize-ManagedChild {
    if ('NexusAcceptanceChild' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

// 仅移植 accept_job_restart.py 的挂起创建、先归属后恢复和专用 Job 收口。
public sealed class NexusAcceptanceChild : IDisposable {
    [StructLayout(LayoutKind.Sequential)] public struct Security { public int Size; public IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] public bool Inherit; }
    [StructLayout(LayoutKind.Sequential)] public struct Startup {
        public int Size; public IntPtr Reserved, Desktop, Title;
        public uint X, Y, XSize, YSize, XChars, YChars, Fill, Flags;
        public ushort Show, ReservedSize; public IntPtr ReservedBytes, Input, Output, Error;
    }
    [StructLayout(LayoutKind.Sequential)] public struct ProcessInfo { public IntPtr Process, Thread; public uint Id, ThreadId; }
    [StructLayout(LayoutKind.Sequential)] public struct BasicLimits {
        public long ProcessTime, JobTime; public uint Flags; public UIntPtr MinWorkingSet, MaxWorkingSet;
        public uint ActiveLimit; public UIntPtr Affinity; public uint Priority, Scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] public struct IoCounters { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)] public struct ExtendedLimits {
        public BasicLimits Basic; public IoCounters Io; public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }
    [StructLayout(LayoutKind.Sequential)] public struct Accounting {
        public long UserTime, KernelTime, PeriodUser, PeriodKernel;
        public uint Faults, Total, Active, Terminated;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateJobObjectW(IntPtr security, string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job, int type, ref ExtendedLimits limits, uint size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job, int type, out Accounting info, uint size, IntPtr returned);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateJobObject(IntPtr job, uint code);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CreatePipe(out IntPtr read, out IntPtr write, ref Security security, uint size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateFileW(string name, uint access, uint share, ref Security security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateProcessW(string app, StringBuilder command, IntPtr ps, IntPtr ts, bool inherit, uint flags, IntPtr env, string cwd, ref Startup startup, out ProcessInfo info);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    IntPtr job, process, thread;
    bool assigned, verifiedEmpty;
    public int Id { get; private set; }
    public bool IsClosed { get; private set; }
    public StreamReader StandardOutput { get; private set; }
    public StreamReader StandardError { get; private set; }
    public Task OutputCompletion { get; set; }
    static void Check(bool ok, string code) {
        if (!ok) throw new InvalidOperationException(code + "_" + Marshal.GetLastWin32Error());
    }
    static void Close(ref IntPtr handle) {
        if (handle == IntPtr.Zero || handle == new IntPtr(-1)) return;
        Check(CloseHandle(handle), "owned_handle_close_failed"); handle = IntPtr.Zero;
    }
    static string Quote(string value) {
        var text = new StringBuilder("\""); int slashes = 0;
        foreach (char c in value) {
            if (c == '\\') { slashes++; continue; }
            text.Append('\\', c == '"' ? slashes * 2 + 1 : slashes).Append(c); slashes = 0;
        }
        return text.Append('\\', slashes * 2).Append('"').ToString();
    }
    public NexusAcceptanceChild() {
        job = CreateJobObjectW(IntPtr.Zero, null);
        Check(job != IntPtr.Zero, "owned_job_create_failed");
        var limits = new ExtendedLimits(); limits.Basic.Flags = 0x2000; // KILL_ON_JOB_CLOSE；不允许 breakaway。
        try { Check(SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimits>()), "owned_job_limits_failed"); }
        catch { Close(ref job); throw; }
    }
    public void Start(string file, string[] args) {
        if (Id != 0 || IsClosed) throw new InvalidOperationException("owned_process_already_started");
        IntPtr outputRead=IntPtr.Zero, outputWrite=IntPtr.Zero, errorRead=IntPtr.Zero, errorWrite=IntPtr.Zero, input=IntPtr.Zero;
        var security = new Security { Size=Marshal.SizeOf<Security>(), Inherit=true };
        try {
            Check(CreatePipe(out outputRead, out outputWrite, ref security, 0), "stdout_pipe_failed");
            Check(CreatePipe(out errorRead, out errorWrite, ref security, 0), "stderr_pipe_failed");
            Check(SetHandleInformation(outputRead, 1, 0), "stdout_inheritance_failed");
            Check(SetHandleInformation(errorRead, 1, 0), "stderr_inheritance_failed");
            input = CreateFileW("NUL", 0x80000000, 3, ref security, 3, 0, IntPtr.Zero);
            Check(input != new IntPtr(-1), "null_input_failed");
            var startup = new Startup { Size=Marshal.SizeOf<Startup>(), Flags=0x100, Input=input, Output=outputWrite, Error=errorWrite };
            var command = new StringBuilder(Quote(file));
            foreach (string arg in args) command.Append(' ').Append(Quote(arg));
            ProcessInfo created;
            Check(CreateProcessW(file, command, IntPtr.Zero, IntPtr.Zero, true, 0x08000004, IntPtr.Zero, null, ref startup, out created), "child_create_failed");
            process=created.Process; thread=created.Thread; Id=(int)created.Id;
            Check(AssignProcessToJobObject(job, process), "owned_job_assign_failed"); assigned=true;
            StandardOutput = new StreamReader(new FileStream(new SafeFileHandle(outputRead, true), FileAccess.Read, 4096, false), Encoding.UTF8);
            outputRead=IntPtr.Zero;
            StandardError = new StreamReader(new FileStream(new SafeFileHandle(errorRead, true), FileAccess.Read, 4096, false), Encoding.UTF8);
            errorRead=IntPtr.Zero;
            Check(ResumeThread(thread) != uint.MaxValue, "child_resume_failed");
            Close(ref thread);
        } finally {
            Close(ref outputRead); Close(ref outputWrite); Close(ref errorRead); Close(ref errorWrite); Close(ref input);
        }
    }
    public bool WaitForExit(int milliseconds) {
        uint result=WaitForSingleObject(process, (uint)Math.Max(0, milliseconds));
        Check(result == 0 || result == 258, "child_wait_failed"); return result == 0;
    }
    public int ExitCode { get { uint code; Check(GetExitCodeProcess(process, out code), "child_exit_code_failed"); return unchecked((int)code); } }
    public uint ActiveProcesses {
        get {
            if (IsClosed) return 0;
            Accounting info; Check(QueryInformationJobObject(job, 1, out info, (uint)Marshal.SizeOf<Accounting>(), IntPtr.Zero), "owned_job_query_failed");
            return info.Active;
        }
    }
    public bool ContainsPid(int pid) {
        if (IsClosed) return false;
        IntPtr handle=OpenProcess(0x1000, false, (uint)pid);
        Check(handle != IntPtr.Zero, "owned_member_open_failed");
        try { bool member; Check(IsProcessInJob(handle, job, out member), "owned_member_query_failed"); return member; }
        finally { Close(ref handle); }
    }
    public void Stop(int milliseconds) {
        if (IsClosed) return;
        var timer=Stopwatch.StartNew();
        // 挂入 Job 失败的进程仍是本对象持有的挂起进程，尚不可能创建后代。
        if (process != IntPtr.Zero && !assigned && !WaitForExit(0)) {
            Check(TerminateProcess(process, 1), "suspended_child_stop_failed");
            if (!WaitForExit(milliseconds)) throw new InvalidOperationException("suspended_child_stop_timeout");
        }
        if (ActiveProcesses != 0) Check(TerminateJobObject(job, 1), "owned_job_stop_failed");
        while (ActiveProcesses != 0) {
            if (timer.ElapsedMilliseconds >= milliseconds) throw new InvalidOperationException("owned_descendants_stop_timeout");
            Thread.Sleep(20);
        }
        if (process != IntPtr.Zero && !WaitForExit(Math.Max(0, milliseconds-(int)timer.ElapsedMilliseconds)))
            throw new InvalidOperationException("owned_parent_stop_timeout");
        if (OutputCompletion != null) {
            int left=Math.Max(0, milliseconds-(int)timer.ElapsedMilliseconds);
            if (!OutputCompletion.Wait(left)) throw new InvalidOperationException("owned_output_close_timeout");
        }
        verifiedEmpty=true;
    }
    public void Dispose() {
        if (IsClosed) return;
        if (!verifiedEmpty) throw new InvalidOperationException("owned_cleanup_unverified");
        StandardOutput?.Dispose(); StandardError?.Dispose();
        Close(ref thread); Close(ref process); Close(ref job); IsClosed=true;
    }
}
'@
}
function Set-Phase([string]$Name, [string]$PreviousResult = 'passed') {
    $now = $clock.ElapsedMilliseconds
    if ($script:phaseStartedMs -ge 0) {
        Write-Host ([ordered]@{ event = 'phase_end'; phase = $report.phase; result = $PreviousResult; elapsed_ms = ($now - $script:phaseStartedMs) } | ConvertTo-Json -Compress)
    }
    $script:phaseStartedMs = $now
    if ($Name) {
        $report.phase = $Name
        Write-Host ([ordered]@{ event = 'phase_start'; phase = $Name; elapsed_ms = $now } | ConvertTo-Json -Compress)
    }
}
function Assert-ActionsRunner {
    Require ($PSVersionTable.PSVersion.Major -ge 7 -and [Environment]::OSVersion.Platform -eq 'Win32NT') 'windows_pwsh_required'
    Require ($env:GITHUB_ACTIONS -ceq 'true' -and $env:RUNNER_ENVIRONMENT -ceq 'github-hosted') 'hosted_actions_required'
    Require ($env:RUNNER_OS -ceq 'Windows' -and $env:ImageOS -ceq 'win22') 'windows_2022_required'
    Require ($env:GITHUB_REPOSITORY -ceq 'yccwh2008/nexus-releases' -and $env:GITHUB_SERVER_URL -ceq 'https://github.com') 'repository_not_allowed'
    Require ($env:GITHUB_EVENT_NAME -ceq 'workflow_dispatch') 'manual_dispatch_required'
    Require ([bool]$env:GITHUB_EVENT_PATH -and (Test-Path -LiteralPath $env:GITHUB_EVENT_PATH -PathType Leaf)) 'event_missing'
    $event = Get-Content -LiteralPath $env:GITHUB_EVENT_PATH -Raw | ConvertFrom-Json
    Require ($event.repository.full_name -ceq 'yccwh2008/nexus-releases' -and $event.repository.private -ceq $false) 'public_repository_required'
    Require ($env:GITHUB_REF -ceq ('refs/heads/' + $event.repository.default_branch)) 'default_branch_required'
    Require ([bool]$env:RUNNER_TEMP -and (Test-Path -LiteralPath $env:RUNNER_TEMP -PathType Container)) 'runner_temp_missing'
    Require ([bool]$env:GITHUB_STEP_SUMMARY) 'summary_missing'
    $tempPrefix = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\') + '\'
    Require ([IO.Path]::GetFullPath($env:GITHUB_STEP_SUMMARY).StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) 'summary_outside_runner_temp'
    Require (@(Get-ChildItem Env: | Where-Object Name -Like 'NEXUS_*').Count -eq 0) 'unexpected_nexus_environment'
}

function Budget([int]$Seconds) {
    $remaining = [int][Math]::Floor(1020 - $clock.Elapsed.TotalSeconds)
    Require ($remaining -gt 0) 'acceptance_deadline_exceeded'
    return [Math]::Min($Seconds, $remaining)
}

function Assert-PortFree {
    $listeners = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()
    Require (@($listeners | Where-Object Port -EQ 8760).Count -eq 0) 'port_8760_in_use'
}

function Assert-FileHash([string]$Path, [string]$Hash, [long]$Size = 0) {
    Require ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ieq $Hash) 'asset_hash_mismatch'
    if ($Size) { Require ((Get-Item -LiteralPath $Path).Length -eq $Size) 'asset_size_mismatch' }
}

# 保留自身创建的进程句柄；不按名称或端口批量终止进程。
function Invoke-Child([string]$File, [string[]]$Arguments, [int]$Seconds = 120, [string]$ServiceVersion = '') {
    Initialize-ManagedChild
    $deadlineMs = $clock.Elapsed.TotalMilliseconds + (Budget $Seconds) * 1000
    $process = [NexusAcceptanceChild]::new()
    $managedChildren.Add($process) # 先登记，再创建任何进程；覆盖安装器、检查器和 launcher。
    $record = $null
    $retain = $false
    try {
        $started = [DateTime]::UtcNow
        $process.Start($File, $Arguments)
        if ($ServiceVersion) {
            $versionRoot = Join-Path $install "versions/$ServiceVersion"
            $record = [pscustomobject]@{ Parent = $process.Id; Started = $started; Ended = [DateTime]::MaxValue; Version = $ServiceVersion; Python = (Join-Path $versionRoot 'runtime/python.exe'); Entry = (Join-Path $versionRoot 'start.py'); Owner = $process }
            $launches.Add($record)
        }
        $stdout = if ($ServiceVersion) {
            $process.StandardOutput.BaseStream.CopyToAsync([IO.Stream]::Null)
        } else {
            $process.StandardOutput.ReadToEndAsync()
        }
        $stderr = $process.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null)
        $process.OutputCompletion = [Threading.Tasks.Task]::WhenAll([Threading.Tasks.Task[]]@($stdout, $stderr))
        $remainingMs = [int][Math]::Floor([Math]::Min($deadlineMs, 1020000) - $clock.Elapsed.TotalMilliseconds)
        if ($remainingMs -le 0 -or -not $process.WaitForExit($remainingMs)) { throw 'child_timeout' }
        Require ($process.ExitCode -eq 0) 'child_failed'
        if ($ServiceVersion) { $retain = $true; return '' } # 保留 Job 和读端至对应停止阶段。
        $remainingMs = [int][Math]::Floor([Math]::Min($deadlineMs, 1020000) - $clock.Elapsed.TotalMilliseconds)
        if ($remainingMs -le 0 -or -not $process.OutputCompletion.Wait($remainingMs)) { throw 'child_output_timeout' }
        return $stdout.GetAwaiter().GetResult() # 两个输出任务均已在剩余预算内完成。
    }
    finally {
        if ($record) { $record.Ended = [DateTime]::UtcNow }
        if (-not $retain) {
            try { $process.Stop(5000); $process.Dispose(); $null = $managedChildren.Remove($process) }
            catch { $script:cleanupFailed = $true; throw } # 保留失败对象，最终收口仍会重试，不能误报 true。
        }
    }
}

function Get-OwnedServices {
    foreach ($launch in $launches) {
        if ($launch.Owner.IsClosed) { continue }
        $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $($launch.Parent)" -ErrorAction Stop)
        foreach ($child in $children) {
            $created = $child.CreationDate.ToUniversalTime()
            $command = '^"?' + [regex]::Escape($launch.Python) + '"?\s+"?' + [regex]::Escape($launch.Entry) + '"?\s*$'
            if ($created -ge $launch.Started -and $created -le $launch.Ended -and $child.ExecutablePath -ieq $launch.Python -and $child.CommandLine -imatch $command -and $launch.Owner.ContainsPid([int]$child.ProcessId)) {
                [pscustomobject]@{ Id = [int]$child.ProcessId; Created = $created; Version = $launch.Version }
            }
        }
    }
}

function Assert-ServiceOwner {
    $connections = @(Get-NetTCPConnection -State Listen -LocalPort 8760 -ErrorAction Stop)
    Require ($connections.Count -eq 1 -and $connections[0].LocalAddress -eq '127.0.0.1') 'listener_not_loopback'
    $owned = @(Get-OwnedServices | Where-Object { $_.Id -eq $connections[0].OwningProcess -and $_.Version -eq $activeVersion })
    Require ($owned.Count -eq 1) 'listener_not_owned'
    return $owned[0]
}

function Stop-OwnedServices {
    # Job 句柄是归属依据；父进程先退出、后代换父或尚未进入 ServiceVersion 也不会漏收。
    foreach ($process in @($managedChildren.ToArray())) {
        try { $process.Stop(10000); $process.Dispose(); $null = $managedChildren.Remove($process) }
        catch { $script:cleanupFailed = $true } # 单个失败不阻止回收其他本任务 Job。
    }
    Require (-not $cleanupFailed -and $managedChildren.Count -eq 0) 'owned_process_cleanup_failed'
}

# HttpClient 不跟随任何重定向，保留默认 TLS 校验；仅本次请求不使用代理。
function Request([string]$Uri, [string]$Method = 'GET', [int]$Status = 200, [int]$Seconds = 30, [string]$Destination = '', [long]$Limit = 1048576, [hashtable]$Form = @{}) {
    $local = $Uri.StartsWith('http://127.0.0.1:8760/', [StringComparison]::Ordinal)
    Require ($local -or $Uri.StartsWith($site, [StringComparison]::Ordinal)) 'request_origin_not_allowed'
    if ($local) { $null = Assert-ServiceOwner }
    $cancel = [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds((Budget $Seconds)))
    $message = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method), $Uri)
    $response = $null
    $stream = $null
    $output = $null
    try {
        if ($Method -eq 'POST') {
            $fields = [Collections.Generic.Dictionary[string,string]]::new()
            foreach ($key in $Form.Keys) { $fields.Add($key, [string]$Form[$key]) }
            $message.Content = [Net.Http.FormUrlEncodedContent]::new($fields)
        }
        $response = $client.SendAsync($message, [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cancel.Token).GetAwaiter().GetResult()
        Require ([int]$response.StatusCode -eq $Status) 'http_status_unexpected'
        Require ($response.Content.Headers.ContentLength -le $Limit) 'response_too_large'
        $stream = $response.Content.ReadAsStreamAsync($cancel.Token).GetAwaiter().GetResult()
        $output = if ($Destination) { [IO.File]::Open($Destination, [IO.FileMode]::CreateNew) } else { [IO.MemoryStream]::new() }
        $buffer = [byte[]]::new(65536)
        [long]$total = 0
        while (($count = $stream.ReadAsync($buffer, 0, $buffer.Length, $cancel.Token).GetAwaiter().GetResult()) -gt 0) {
            $total += $count
            Require ($total -le $Limit) 'response_too_large'
            $output.Write($buffer, 0, $count)
        }
        $body = if ($Destination) { '' } else { [Text.Encoding]::UTF8.GetString($output.ToArray()) }
        return [pscustomobject]@{ Body = $body; Location = [string]$response.Headers.Location; Bytes = $total }
    }
    finally {
        if ($output) { $output.Dispose() }; if ($stream) { $stream.Dispose() }; if ($response) { $response.Dispose() }
        $message.Dispose(); $cancel.Dispose()
    }
}

function Get-Pointers {
    $state = [ordered]@{}
    foreach ($name in @('current', 'previous', 'pending')) {
        $path = Join-Path $install "$name.json"
        $state[$name] = $null
        $state["${name}_sha256"] = $null
        if (Test-Path -LiteralPath $path) {
            $state[$name] = (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).version
            $state["${name}_sha256"] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        }
    }
    return $state
}

# 只读 SQLite/包内容，或制造一个小型损坏 ZIP；不导入或仿写升级实现。
$pythonChecks = @"
import hashlib, json, re, sqlite3, sys, zipfile
from pathlib import Path
from contextlib import closing
mode, *args = sys.argv[1:]
if mode == 'package':
    directory, archive, external, version = map(str, args)
    root = Path(directory)
    outer = json.loads(Path(external).read_text(encoding='utf-8'))
    with zipfile.ZipFile(archive) as z:
        inner = json.loads(z.read('manifest.json'))
    installed = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
    assert outer['version'] == version
    for key in ('version', 'schema_version', 'file_hashes'):
        assert inner[key] == outer[key] == installed[key]
    for name, expected in outer['file_hashes'].items():
        path = (root / name).resolve()
        assert path.is_relative_to(root.resolve())
        assert path.stat().st_size == expected['size']
        with path.open('rb') as f:
            assert hashlib.file_digest(f, 'sha256').hexdigest() == expected['sha256']
    text = (root / 'app/nexus/__init__.py').read_text(encoding='utf-8')
    assert re.search(r'__version__\s*=\s*[' + chr(34) + chr(39) + r']([^' + chr(34) + chr(39) + r']+)', text).group(1) == version
    print(json.dumps({'version': version, 'files': len(outer['file_hashes'])}))
elif mode == 'job':
    database, job_id = args
    with closing(sqlite3.connect(Path(database).resolve().as_uri() + '?mode=ro', uri=True, timeout=5)) as db:
        db.row_factory = sqlite3.Row
        db.execute('BEGIN')
        assert db.execute('SELECT count(*) FROM job').fetchone()[0] == 1
        assert db.execute('SELECT count(*) FROM credential').fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM schedule').fetchone()[0] == 0
        job = dict(db.execute('SELECT * FROM job WHERE id=?', (int(job_id),)).fetchone())
        assert job['module_id'] == 'sample' and job['error'] is None
        inbox = [dict(r) for r in db.execute('SELECT * FROM inbox_item WHERE job_id=? ORDER BY id', (int(job_id),))]
        steps = [dict(r) for r in db.execute('SELECT * FROM job_step WHERE job_id=? ORDER BY id', (int(job_id),))]
        snapshot = json.dumps([job, inbox, steps], sort_keys=True, separators=(',', ':')).encode()
        print(json.dumps({'state': job['state'], 'inbox_id': inbox[0]['id'] if len(inbox) == 1 else None,
            'resolved': bool(inbox[0]['resolved']) if len(inbox) == 1 else False, 'steps': len(steps),
            'sha256': hashlib.sha256(snapshot).hexdigest()}))
elif mode == 'corrupt':
    root = Path(args[0]); archive = root / 'corrupt.zip'
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr('probe.txt', b'no business data')
    data = archive.read_bytes()[:-22]  # 删除 EOCD；外部摘要匹配，让正式接口确实解析坏 ZIP。
    archive.write_bytes(data)
    manifest = {'version': '0.1.2', 'schema_version': 1, 'file_hashes': {},
        'archive': {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}}
    (root / 'corrupt.manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
    assert len(data) < 1024 and not zipfile.is_zipfile(archive)
    print('{}')
else:
    raise ValueError('unknown_check')
"@

function Python-Check([string[]]$Arguments) {
    return (Invoke-Child -File $python -Arguments (@('-I', '-B', '-c', $pythonChecks) + $Arguments) -Seconds 120 | ConvertFrom-Json)
}

function Wait-Sample([string]$State) {
    $deadline = [DateTime]::UtcNow.AddSeconds((Budget 30))
    do {
        $snapshot = Python-Check @('job', $database, [string]$jobId)
        Require ($snapshot.state -notin @('failed', 'cancelled')) 'sample_failed'
        if ($snapshot.state -eq $State -and $snapshot.inbox_id) { return $snapshot }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'sample_timeout'
}

try {
    Set-Phase 'guard'
    Assert-ActionsRunner
    $summaryAllowed = $true
    Assert-PortFree
    $shell = New-Object -ComObject WScript.Shell
    $shortcuts = @('Desktop', 'Startup') | ForEach-Object { Join-Path $shell.SpecialFolders.Item($_) 'Nexus.lnk' }
    foreach ($shortcut in $shortcuts) { Require (-not (Test-Path -LiteralPath $shortcut)) 'existing_nexus_shortcut' }
    $root = Join-Path $env:RUNNER_TEMP ('nexus-acceptance-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $root
    $install = Join-Path $root 'install'
    $database = Join-Path $root 'data/nexus.db'
    $env:NEXUS_APP_DATA_DIR = Join-Path $root 'data'
    $env:NEXUS_DB_PATH = $database
    $env:NEXUS_UPDATE_INSTALL_ROOT = $install
    $environmentSet = $true
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.UseProxy = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [Threading.Timeout]::InfiniteTimeSpan
    Set-Phase 'pinned_downloads'
    $pins = @(
        @{ Name = 'install.ps1'; Size = 0; Limit = 65536; Hash = 'a45a9052b3801388d79475ae3e998e1d1103ad7d22f98c5e32166cdb7bb46642' },
        @{ Name = 'Nexus-0.1.0.zip'; Size = 141872574; Limit = 141872574; Hash = '5917a1436d59cb252bbc0b54f9eb546a9f482857dd6f30da4c863152f332870c' },
        @{ Name = 'Nexus-0.1.0.manifest.json'; Size = 0; Limit = 16777216; Hash = '465e1000e6ef24c42017628f8745fdf94177458fbbd84fc3d657404787609cbe' },
        @{ Name = 'Nexus-0.1.1.zip'; Size = 123515740; Limit = 123515740; Hash = '6d121f50f65a94c048eebdf2734b2476e0c9fb9d4fbbd11f508d2f794e0d68dc' },
        @{ Name = 'Nexus-0.1.1.manifest.json'; Size = 0; Limit = 1048576; Hash = 'd5ee850ac116effcdb21aecccafd874bc6e35e285d0a381ffd073492f0ccda11' }
    )
    foreach ($pin in $pins) {
        $path = Join-Path $root $pin.Name
        $null = Request -Uri ($site + $pin.Name) -Destination $path -Limit $pin.Limit -Seconds 180
        Assert-FileHash $path $pin.Hash $pin.Size
    }
    $catalog = (Request -Uri ($site + 'latest.json') -Limit 65536).Body | ConvertFrom-Json
    Require ($catalog.version -ceq '0.1.1' -and $catalog.archive -ceq 'Nexus-0.1.1.zip' -and $catalog.manifest -ceq 'Nexus-0.1.1.manifest.json' -and $catalog.archive_size -eq 123515740 -and $catalog.archive_sha256 -ceq $pins[3].Hash) 'catalog_not_pinned_target'
    foreach ($version in @('0.1.0', '0.1.1')) {
        $manifest = Get-Content -LiteralPath (Join-Path $root "Nexus-$version.manifest.json") -Raw | ConvertFrom-Json
        $pin = $pins | Where-Object Name -EQ "Nexus-$version.zip"
        Require ($manifest.version -ceq $version -and $manifest.archive.sha256 -ceq $pin.Hash -and $manifest.archive.size -eq $pin.Size) 'manifest_archive_mismatch'
    }
    $report.checks += 'all_five_asset_pins_verified'
    Set-Phase 'baseline_install'
    $powershell = (Get-Command powershell.exe -ErrorAction Stop).Source
    $null = Invoke-Child -File $powershell -Arguments @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $root 'install.ps1'), '-Zip', (Join-Path $root 'Nexus-0.1.0.zip'), '-Manifest', (Join-Path $root 'Nexus-0.1.0.manifest.json'), '-InstallRoot', $install) -Seconds 240
    $launcher = Join-Path $install 'launcher.ps1'
    $launcherHash = (Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash
    for ($i = 0; $i -lt $shortcuts.Count; $i++) {
        Require (Test-Path -LiteralPath $shortcuts[$i] -PathType Leaf) 'shortcut_missing'
        $shortcut = $shell.CreateShortcut($shortcuts[$i])
        $expected = '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $launcher + '"'
        if ($i -eq 1) { $expected += ' -NoBrowser' }
        Require ($shortcut.TargetPath -ieq $powershell -and $shortcut.Arguments -ceq $expected -and $shortcut.WorkingDirectory -ieq $install) 'shortcut_target_mismatch'
    }
    $pointers = Get-Pointers
    Require ($pointers.current -ceq '0.1.0' -and -not $pointers.pending -and -not $pointers.previous) 'baseline_pointer_mismatch'
    $python = Join-Path $install 'versions/0.1.0/runtime/python.exe'
    $null = Python-Check @('package', (Join-Path $install 'versions/0.1.0'), (Join-Path $root 'Nexus-0.1.0.zip'), (Join-Path $root 'Nexus-0.1.0.manifest.json'), '0.1.0')
    $report.checks += 'baseline_and_shortcuts_verified'
    Set-Phase 'sample'
    Assert-PortFree
    $env:NEXUS_UPDATE_CATALOG_URL = $site + 'latest.json'
    $null = Invoke-Child -File $powershell -Arguments @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $launcher, '-NoBrowser') -Seconds 90 -ServiceVersion '0.1.0'
    $activeVersion = '0.1.0'
    $baselineProcess = Assert-ServiceOwner
    $health = (Request -Uri 'http://127.0.0.1:8760/health').Body | ConvertFrom-Json
    Require ($health.service -ceq 'nexus' -and $health.status -ceq 'ok') 'baseline_health_invalid'
    $created = Request -Uri 'http://127.0.0.1:8760/run/sample' -Method POST -Status 302
    Require ($created.Location -match '^/jobs/([1-9][0-9]*)$') 'sample_location_invalid'
    $jobId = [int]$Matches[1]
    $waiting = Wait-Sample 'waiting_human'
    $inbox = Request -Uri 'http://127.0.0.1:8760/inbox'
    Require ($inbox.Body.Contains('/inbox/' + $waiting.inbox_id + '/continue')) 'sample_inbox_action_missing'
    $continued = Request -Uri ('http://127.0.0.1:8760/inbox/' + $waiting.inbox_id + '/continue') -Method POST -Status 302
    Require ($continued.Location -ceq "/jobs/$jobId") 'sample_continue_mismatch'
    $sample = Wait-Sample 'succeeded'
    Require ($sample.resolved -and $sample.steps -ge 2) 'sample_not_resolved'
    $report.checks += 'sample_succeeded_without_credentials_or_schedules'
    Set-Phase 'remote_upgrade'
    $status = (Request -Uri 'http://127.0.0.1:8760/upgrade/status').Body | ConvertFrom-Json
    Require ($status.configured -eq $true -and $status.available -eq $true -and $status.version -ceq '0.1.1' -and -not $status.error) 'target_not_discovered'
    $null = Request -Uri 'http://127.0.0.1:8760/upgrade/download' -Method POST -Status 302 -Seconds 300
    $pointers = Get-Pointers
    Require ($pointers.current -ceq '0.1.0' -and $pointers.pending -ceq '0.1.1' -and -not $pointers.previous) 'staged_pointer_mismatch'
    Require ((Assert-ServiceOwner).Id -eq $baselineProcess.Id) 'baseline_process_replaced_early'
    $null = Python-Check @('package', (Join-Path $install 'versions/0.1.1'), (Join-Path $root 'Nexus-0.1.1.zip'), (Join-Path $root 'Nexus-0.1.1.manifest.json'), '0.1.1')
    $report.checks += 'real_download_staged_without_activation'
    Set-Phase 'launcher_activation'
    Stop-OwnedServices
    Assert-PortFree
    Remove-Item Env:NEXUS_UPDATE_CATALOG_URL
    Assert-FileHash $launcher $launcherHash
    $null = Invoke-Child -File $powershell -Arguments @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $launcher, '-NoBrowser') -Seconds 90 -ServiceVersion '0.1.1'
    $activeVersion = '0.1.1'
    $null = Assert-ServiceOwner
    $health = (Request -Uri 'http://127.0.0.1:8760/health').Body | ConvertFrom-Json
    Require ($health.service -ceq 'nexus' -and $health.status -ceq 'ok') 'target_health_invalid'
    $pointers = Get-Pointers
    Require ($pointers.current -ceq '0.1.1' -and $pointers.previous -ceq '0.1.0' -and -not (Test-Path -LiteralPath (Join-Path $install 'pending.json'))) 'activated_pointer_mismatch'
    $python = Join-Path $install 'versions/0.1.1/runtime/python.exe'
    $retained = Python-Check @('job', $database, [string]$jobId)
    Require ($retained.state -ceq 'succeeded' -and $retained.resolved -and $retained.sha256 -ceq $sample.sha256) 'sample_not_retained'
    $status = (Request -Uri 'http://127.0.0.1:8760/upgrade/status').Body | ConvertFrom-Json
    Require ($status.configured -eq $true -and $status.available -eq $false -and -not $status.error -and -not (Test-Path Env:NEXUS_UPDATE_CATALOG_URL)) 'default_update_source_failed'
    $report.checks += 'new_process_pointers_data_and_default_source_verified'
    Set-Phase 'corrupt_zip'
    $before = Get-Pointers | ConvertTo-Json -Compress
    $null = Python-Check @('corrupt', $root)
    $rejected = Request -Uri 'http://127.0.0.1:8760/upgrade/stage' -Method POST -Status 400 -Form @{ archive_path = (Join-Path $root 'corrupt.zip'); manifest_path = (Join-Path $root 'corrupt.manifest.json') }
    Require ($rejected.Body.Contains('update_archive_invalid')) 'corrupt_zip_not_rejected'
    Require ((Get-Pointers | ConvertTo-Json -Compress) -ceq $before) 'corrupt_zip_changed_pointers'
    Require (-not (Test-Path -LiteralPath (Join-Path $install 'versions/0.1.2'))) 'corrupt_version_created'
    Assert-FileHash $launcher $launcherHash
    $report.checks += 'corrupt_zip_rejected_with_unchanged_pointers'
    $report.sample = @{ job_id = $jobId; inbox_id = $sample.inbox_id; state = 'succeeded'; retained_sha256 = $sample.sha256 }
    $report.versions = @{ current = '0.1.1'; previous = '0.1.0'; pending = $null }
    $report.result = 'passed'
    Set-Phase 'complete'
}
catch {
    $message = $_.Exception.GetBaseException().Message
    $report.error = if ($message -cmatch '^[a-z][a-z0-9_]{1,70}$') { $message } else { 'unexpected_failure' }
}
finally {
    Set-Phase '' $report.result
    $cleanupStartedMs = $clock.ElapsedMilliseconds
    Write-Host ('{"event":"phase_start","phase":"cleanup","elapsed_ms":' + $cleanupStartedMs + '}')
    try { Stop-OwnedServices; $report.cleanup_owned_processes = $true }
    catch { $report.result = 'failed'; $report.cleanup_owned_processes = $false; $report.error = 'owned_process_cleanup_failed' }
    if ($environmentSet) {
        foreach ($name in @('NEXUS_APP_DATA_DIR', 'NEXUS_DB_PATH', 'NEXUS_UPDATE_INSTALL_ROOT', 'NEXUS_UPDATE_CATALOG_URL')) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
    }
    if ($client) { $client.Dispose() }
    Write-Host ([ordered]@{ event = 'phase_end'; phase = 'cleanup'; result = $(if ($report.cleanup_owned_processes) { 'passed' } else { 'failed' }); elapsed_ms = ($clock.ElapsedMilliseconds - $cleanupStartedMs) } | ConvertTo-Json -Compress)
    $report.elapsed_seconds = [int]$clock.Elapsed.TotalSeconds
    $json = $report | ConvertTo-Json -Depth 5
    Write-Output $json
    if ($summaryAllowed) { Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Encoding utf8 -Value ("## Windows release acceptance`n``````json`n" + $json + "`n``````") }
}
if ($report.result -ne 'passed') { exit 1 }
