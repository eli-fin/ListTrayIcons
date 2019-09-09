//todo: test on 32, especially the tooltip extraction, then update readme
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media.Imaging;

namespace ListTrayIcons
{
    public static class IconLister
    {
        private static bool _initialized;
        private static UIntPtr iconWindow;
        private static int explorerPid;

        // Because we are reading data and passing pointers to and from the explorer process, the current process
        // must have the same bitness as the os (which will match the explorer.exe bitness)
        // (technically, x64 should be able to work on x86 too, but it's simpler if they are just the same)
        private static void AssertBitness()
        {
            const string X64 = "x64", X86 = "x86";

            string curProcBitness = IntPtr.Size == 8 ? X64 : X86;
            string osBitness;
            if (curProcBitness == X64)
            {
                osBitness = X64; // If the process is 64, OS must be 64
            }
            else
            {
                using (Process p = Process.GetCurrentProcess())
                {
                    try
                    {
                        bool ret = Win32.IsWow64Process((UIntPtr)(long)p.Handle, out bool isWow64);
                        Win32.ThrowOnError(!ret, Marshal.GetLastWin32Error(), "IsWow64Process");
                        osBitness = isWow64 ? X64 : X86;
                    }
                    catch (EntryPointNotFoundException) // OS does not have this method, so it's old and is for sure not x64
                    {
                        osBitness = X86;
                    }
                }
            }

            if (curProcBitness != osBitness)
                throw new Exception($"This app must run as the same bitness of the host OS (not OS={osBitness}, Process={curProcBitness})");
        }

        private static void Init()
        {
            _initialized = true;

            AssertBitness();

            // Find the actual task bar sub-window containing all the icons (each of which is a button on that window)

            // From looking at spyxx, this is the hierarchy
            UIntPtr win = Win32.FindWindow("Shell_TrayWnd", null);
            Win32.ThrowOnError(win == UIntPtr.Zero, Marshal.GetLastWin32Error(), "FindWindow Shell_TrayWnd");
            win = Win32.FindWindowEx(win, UIntPtr.Zero, "TrayNotifyWnd", null);
            Win32.ThrowOnError(win == UIntPtr.Zero, Marshal.GetLastWin32Error(), "FindWindowEx TrayNotifyWnd");
            win = Win32.FindWindowEx(win, UIntPtr.Zero, "SysPager", null);
            Win32.ThrowOnError(win == UIntPtr.Zero, Marshal.GetLastWin32Error(), "FindWindowEx SysPager");
            win = Win32.FindWindowEx(win, UIntPtr.Zero, null, "User Promoted Notification Area");
            Win32.ThrowOnError(win == UIntPtr.Zero, Marshal.GetLastWin32Error(), "FindWindowEx User Promoted Notification Area");

            iconWindow = win;

            // Get the explorer process id
            int ret = Win32.GetWindowThreadProcessId(iconWindow, out explorerPid);
            Win32.ThrowOnError(ret == 0, Marshal.GetLastWin32Error(), "GetWindowThreadProcessId for explorer");
        }

        public static List<TrayIconInfo> List()
        {
            if (!_initialized)
                Init();

            List<TrayIconInfo> retval = new List<TrayIconInfo>();

            // btnPtr: this is a pointer sized remote buffer that we can pass to send message, which will put the btn address in it
            // btn: the remote btn object
            // reader: use to read remote data
            using (RemoteProcBuffer btnPtr = new RemoteProcBuffer(explorerPid, (uint)UIntPtr.Size))
            using (RemoteProcBuffer btn = new RemoteProcBuffer(explorerPid, (uint)Math.Max(Marshal.SizeOf(typeof(Win32.Structs.TBBUTTONx64)), Marshal.SizeOf(typeof(Win32.Structs.TBBUTTONx86)))))
            using (RemoteProcReader reader = new RemoteProcReader(explorerPid))
            {
                int iconCount = (int)Win32.SendMessage(iconWindow, Win32.Constants.TB_BUTTONCOUNT, IntPtr.Zero, IntPtr.Zero);

                for (int i = 0; i < iconCount; ++i)
                {
                    // Get address of btn struct
                    Win32.SendMessage(iconWindow, Win32.Constants.TB_GETBUTTON, (IntPtr)i, (IntPtr)(long)btnPtr.BufAddr);

                    // Now get the string address, trayData and whether it's hidden
                    UIntPtr iString;
                    bool isHidden;
                    Win32.Structs.TRAYDATA trayData;
                    if (IntPtr.Size == 8) // We need a separate struct for each bitness
                    {
                        Win32.Structs.TBBUTTONx64 btnObj = reader.ReadObj<Win32.Structs.TBBUTTONx64>(btnPtr.BufAddr);
                        iString = btnObj.iString;
                        isHidden = (btnObj.fsState & Win32.Constants.TBSTATE_HIDDEN) != 0;
                        trayData = reader.ReadObj<Win32.Structs.TRAYDATA>(btnObj.dwData);
                    }
                    else
                    {
                        Win32.Structs.TBBUTTONx86 btnObj = reader.ReadObj<Win32.Structs.TBBUTTONx86>(btnPtr.BufAddr);
                        iString = btnObj.iString;
                        isHidden = (btnObj.fsState & Win32.Constants.TBSTATE_HIDDEN) != 0;
                        trayData = reader.ReadObj<Win32.Structs.TRAYDATA>(btnObj.dwData);
                    }

                    int ret = Win32.GetWindowThreadProcessId(trayData.hwnd, out int iconPid);
                    Win32.ThrowOnError(ret == 0, Marshal.GetLastWin32Error(), "GetWindowThreadProcessId for icon");

                    string fileName;
                    BitmapSource bitmap = null;
                    try
                    {
                        fileName = Process.GetProcessById(iconPid).MainModule.FileName;
                        try
                        {
                            bitmap = Imaging.CreateBitmapSourceFromHIcon((IntPtr)(long)trayData.hIcon, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
                        }
                        catch { } // err, do something, but what?
                    }
                    catch (Exception e)
                    {
                        fileName = $"error [{e.Message}]";
                    }

                    // Get the tool tip, one char at a time
                    List<char> tooTipCharList = new List<char>();
                    short c; // Use short, so the size is 2 bytes, since it's a wide char
                    while ((c = reader.ReadObj<short>((UIntPtr)((uint)iString + (tooTipCharList.Count * Marshal.SizeOf(typeof(short)))))) != '\0')
                    {
                        tooTipCharList.Add((char)c);
                    }

                    retval.Add(new TrayIconInfo { FileName = fileName, PID = iconPid, Bitmap = bitmap, IsHidden = isHidden, ToolTip = new string(tooTipCharList.ToArray()) });
                }
            }

            return retval;
        }
    }

    // A class to read data from a remote process
    public class RemoteProcReader : IDisposable
    {
        private readonly UIntPtr process;

        public RemoteProcReader(int pid)
        {
            process = Win32.OpenProcess(Win32.Flags.ProcessAccessFlags.VirtualMemoryOperation | Win32.Flags.ProcessAccessFlags.VirtualMemoryRead, false, pid);
            Win32.ThrowOnError(process == UIntPtr.Zero, Marshal.GetLastWin32Error(), "OpenProcess");
        }

        // Read size bytes from address
        public byte[] ReadBuf(UIntPtr address, int size)
        {
            byte[] buf = new byte[size];
            bool ret = Win32.ReadProcessMemory(process, address, buf, (IntPtr)size, out IntPtr _);
            Win32.ThrowOnError(!ret, Marshal.GetLastWin32Error(), "ReadProcessMemory");
            return buf;
        }

        // Read object from address
        public T ReadObj<T>(UIntPtr address) where T: struct
        {
            byte[] buf = ReadBuf(address, Marshal.SizeOf(typeof(T)));
            GCHandle pinnedBuf = GCHandle.Alloc(buf, GCHandleType.Pinned);
            T ret = (T)Marshal.PtrToStructure(pinnedBuf.AddrOfPinnedObject(), typeof(T));
            pinnedBuf.Free();
            return ret;
        }

        public void Dispose()
        {
            bool ret = Win32.CloseHandle(process);
            Win32.ThrowOnError(!ret, Marshal.GetLastWin32Error(), "CloseHandle");
        }
    }

    // A class which allocates a buffer in a remote process and allows getting it's address (in the remote process) and writing data to the buffer
    public class RemoteProcBuffer : IDisposable
    {
        public UIntPtr BufAddr { get { return _BufAddr; } }

        private readonly UIntPtr _BufAddr;
        private readonly UIntPtr process;
        private readonly uint bufSize;

        public RemoteProcBuffer(int pid, uint bufSize)
        {
            this.bufSize = bufSize;
            process = Win32.OpenProcess(Win32.Flags.ProcessAccessFlags.VirtualMemoryOperation | Win32.Flags.ProcessAccessFlags.VirtualMemoryRead, false, pid);
            Win32.ThrowOnError(process == UIntPtr.Zero, Marshal.GetLastWin32Error(), "OpenProcess");
            _BufAddr = Win32.VirtualAllocEx(process, UIntPtr.Zero, bufSize, Win32.Flags.AllocationType.Commit | Win32.Flags.AllocationType.Reserve, Win32.Flags.MemoryProtection.ReadWrite);
            Win32.ThrowOnError(_BufAddr == UIntPtr.Zero, Marshal.GetLastWin32Error(), "VirtualAllocEx");
        }

        // Write data to remote buffer
        public int Write(byte[] data)
        {
            if (data.Length > bufSize)
                throw new Exception("Can't write data larger than the originally allocated bufffer");
            bool ret = Win32.WriteProcessMemory(process, BufAddr, data, (IntPtr)data.Length, out IntPtr len);
            Win32.ThrowOnError(!ret, Marshal.GetLastWin32Error(), "WriteProcessMemory");
            return (int)len;
        }

        public void Dispose()
        {
            // Free the memory and close the handle
            bool ret = Win32.VirtualFreeEx(process, BufAddr, 0, Win32.Flags.AllocationType.Release);
            Win32.ThrowOnError(!ret, Marshal.GetLastWin32Error(), "VirtualFreeEx");
            ret = Win32.CloseHandle(process);
            Win32.ThrowOnError(!ret, Marshal.GetLastWin32Error(), "CloseHandle");
        }
    }

    static class Win32
    {
        [DllImport("user32", SetLastError = true)]
        public static extern UIntPtr FindWindow(string lpszClass, string lpszWindow);

        [DllImport("user32", SetLastError = true)]
        public static extern UIntPtr FindWindowEx(UIntPtr hWndParent, UIntPtr hWndChildAfter, string lpszClass, string lpszWindow);

        [DllImport("user32", SetLastError = true)]
        public static extern int GetWindowThreadProcessId(UIntPtr hWnd, out int lpdwProcessId);

        [DllImport("kernel32", SetLastError = true)]
        public static extern UIntPtr OpenProcess(Flags.ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32", SetLastError = true)]
        public static extern UIntPtr VirtualAllocEx(UIntPtr hProcess, UIntPtr lpAddress, uint dwSize, Flags.AllocationType flAllocationType, Flags.MemoryProtection flProtect);

        [DllImport("kernel32", SetLastError = true)]
        public static extern bool VirtualFreeEx(UIntPtr hProcess, UIntPtr lpAddress, int dwSize, Flags.AllocationType dwFreeType);

        [DllImport("kernel32", SetLastError = true)]
        public static extern bool WriteProcessMemory(UIntPtr hProcess, UIntPtr lpBaseAddress, byte[] lpBuffer, IntPtr nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32", SetLastError = true)]
        public static extern bool ReadProcessMemory(UIntPtr hProcess, UIntPtr lpBaseAddress, [Out] byte[] lpBuffer, IntPtr dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32", SetLastError = true)]
        public static extern bool CloseHandle(UIntPtr hObject);

        [DllImport("user32", SetLastError = true)]
        public static extern IntPtr SendMessage(UIntPtr hWnd, int Msg, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32", SetLastError = true)]
        public static extern bool IsWow64Process(UIntPtr hProcess, out bool wow64Process);

        public static void ThrowOnError(bool condition, int errorCode, string msg)
        {
            if (condition)
            {
                if (errorCode == 0)
                    throw new Exception($"Unknown error when '{msg}'");
                string errorText = new System.ComponentModel.Win32Exception(errorCode).Message;
                throw new Exception($"Error '{errorCode} - {errorText}' when '{msg}'");
            }
        }

        public class Constants
        {
            public const int TB_GETBUTTON = 0x0417;
            public const int TB_BUTTONCOUNT = 0x0418;
            public const int TB_GETBUTTONTEXTW = 0x044b;
            public const int TBSTATE_HIDDEN = 0x08;
        }

        public class Structs
        {
            [StructLayout(LayoutKind.Sequential)]
            public struct TBBUTTONx64
            {
                public int iBitmap;
                public int idCommand;
                public byte fsState;
                public byte fsStyle;
                public byte bReserved0, bReserved1, bReserved2, bReserved3, bReserved4, bReserved5;
                public UIntPtr dwData;
                public UIntPtr iString;
            }
            [StructLayout(LayoutKind.Sequential)]
            public struct TBBUTTONx86
            {
                public int iBitmap;
                public int idCommand;
                public byte fsState;
                public byte fsStyle;
                public byte bReserved0, bReserved1;
                public UIntPtr dwData;
                public UIntPtr iString;
            }
            [StructLayout(LayoutKind.Sequential)]
            public struct TRAYDATA
            {
                public UIntPtr hwnd;
                public uint uID;
                public uint uCallbackMessage;
                public int Reserved0, Reserved1;
                public UIntPtr hIcon;
            };
        }

        public class Flags
        {
            [Flags]
            public enum AllocationType : uint
            {
                Commit = 0x1000,
                Reserve = 0x2000,
                Decommit = 0x4000,
                Release = 0x8000,
                Reset = 0x80000,
                Physical = 0x400000,
                TopDown = 0x100000,
                WriteWatch = 0x200000,
                LargePages = 0x20000000
            }

            [Flags]
            public enum MemoryProtection : uint
            {
                Execute = 0x10,
                ExecuteRead = 0x20,
                ExecuteReadWrite = 0x40,
                ExecuteWriteCopy = 0x80,
                NoAccess = 0x01,
                ReadOnly = 0x02,
                ReadWrite = 0x04,
                WriteCopy = 0x08,
                GuardModifierflag = 0x100,
                NoCacheModifierflag = 0x200,
                WriteCombineModifierflag = 0x400
            }

            [Flags]
            public enum ProcessAccessFlags : uint
            {
                All = 0x001F0FFF,
                Terminate = 0x00000001,
                CreateThread = 0x00000002,
                VirtualMemoryOperation = 0x00000008,
                VirtualMemoryRead = 0x00000010,
                VirtualMemoryWrite = 0x00000020,
                DuplicateHandle = 0x00000040,
                CreateProcess = 0x000000080,
                SetQuota = 0x00000100,
                SetInformation = 0x00000200,
                QueryInformation = 0x00000400,
                QueryLimitedInformation = 0x00001000,
                Synchronize = 0x00100000
            }
        }
    }
}

