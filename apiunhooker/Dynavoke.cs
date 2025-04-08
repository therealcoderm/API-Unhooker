using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace ApiUnhooker
{
    public class Dynavoke
    {
        /// <summary>
        /// Resolves the address of an exported function from a module's PE header.
        /// </summary>
        public static IntPtr GetExportAddress(IntPtr moduleBase, string exportName)
        {
            try
            {
                // Read PE Header
                int peHeaderOffset = Marshal.ReadInt32(moduleBase + 0x3C);
                long optionalHeaderBase = moduleBase.ToInt64() + peHeaderOffset + 0x18;
                long magic = Marshal.ReadInt16((IntPtr)optionalHeaderBase);

                long exportTableOffset = (magic == 0x10B) ? optionalHeaderBase + 0x60 : optionalHeaderBase + 0x70;

                int exportRVA = Marshal.ReadInt32((IntPtr)exportTableOffset);
                IntPtr exportDir = (IntPtr)(moduleBase.ToInt64() + exportRVA);

                int ordinalBase = Marshal.ReadInt32(exportDir + 0x10);
                int numberOfNames = Marshal.ReadInt32(exportDir + 0x18);
                int namesRVA = Marshal.ReadInt32(exportDir + 0x20);
                int ordinalsRVA = Marshal.ReadInt32(exportDir + 0x24);
                int functionsRVA = Marshal.ReadInt32(exportDir + 0x1C);

                for (int i = 0; i < numberOfNames; i++)
                {
                    int nameRVA = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + namesRVA + i * 4));
                    string functionName = Marshal.PtrToStringAnsi((IntPtr)(moduleBase.ToInt64() + nameRVA));

                    if (string.Equals(functionName, exportName, StringComparison.OrdinalIgnoreCase))
                    {
                        short ordinal = Marshal.ReadInt16((IntPtr)(moduleBase.ToInt64() + ordinalsRVA + i * 2));
                        int functionRVA = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + functionsRVA + 4 * (ordinal - ordinalBase)));

                        return (IntPtr)(moduleBase.ToInt64() + functionRVA);
                    }
                }

                throw new EntryPointNotFoundException($"Export '{exportName}' not found.");
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to parse module exports.", ex);
            }
        }

        /// <summary>
        /// Dynamically invokes NtProtectVirtualMemory from ntdll.dll.
        /// </summary>
        public static bool NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint newProtect, ref uint oldProtect)
        {
            oldProtect = 0;

            // Get base address of ntdll.dll
            IntPtr ntdllBase = Process.GetCurrentProcess().Modules
                .Cast<ProcessModule>()
                .FirstOrDefault(m => string.Equals(Path.GetFileName(m.FileName), "ntdll.dll", StringComparison.OrdinalIgnoreCase))
                ?.BaseAddress ?? throw new InvalidOperationException("ntdll.dll not found.");

            // Get address of NtProtectVirtualMemory
            IntPtr funcPtr = GetExportAddress(ntdllBase, "NtProtectVirtualMemory");

            // Create delegate and invoke
            var del = (NtProtectVirtualMemoryDelegate)Marshal.GetDelegateForFunctionPointer(funcPtr, typeof(NtProtectVirtualMemoryDelegate));

            object[] args = { processHandle, baseAddress, regionSize, newProtect, oldProtect };
            uint result = (uint)del.DynamicInvoke(args);

            if (result != 0)
                return false;

            oldProtect = (uint)args[4];
            return true;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtProtectVirtualMemoryDelegate(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            ref IntPtr regionSize,
            uint newProtect,
            ref uint oldProtect);
    }
}
