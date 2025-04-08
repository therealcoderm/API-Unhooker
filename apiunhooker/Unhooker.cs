using ApiUnhooker;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace apiunhooker
{
    internal class Unhooker
    {
        public static string[] BlacklistedFunction = new string[]
        {
            "EnterCriticalSection",
            "LeaveCriticalSection",
            "DeleteCriticalSection",
            "InitializeSListHead",
            "HeapAlloc",
            "HeapReAlloc",
            "HeapSize"
        };

        public static bool IsBlacklistedFunction(string FuncName)
        {
            return BlacklistedFunction.Any(f => string.Equals(FuncName, f, StringComparison.OrdinalIgnoreCase));
        }

        public static void Copy(ref byte[] source, int sourceStartIndex, ref byte[] destination, int destinationStartIndex, int length)
        {
            if (source == null || destination == null || length == 0)
                throw new ArgumentNullException("Exception : One or more of the arguments are zero/null!");

            if (length > destination.Length ||
                sourceStartIndex + length > source.Length ||
                destinationStartIndex + length > destination.Length)
                throw new ArgumentOutOfRangeException("Exception : Indices and length out of range!");

            for (int i = 0; i < length; i++)
                destination[destinationStartIndex + i] = source[sourceStartIndex + i];
        }

        public static bool JMPUnhooker(string DLLname)
        {
            string dllPath = Process.GetCurrentProcess().Modules
                .Cast<ProcessModule>()
                .FirstOrDefault(x => DLLname.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase))?.FileName;

            if (dllPath == null) return true;

            byte[] fileBytes = File.ReadAllBytes(dllPath);
            PEReader pereader = new PEReader(fileBytes);
            int textSectionIndex = Array.FindIndex(pereader.ImageSectionHeaders, s => string.Equals(s.Section, ".text", StringComparison.OrdinalIgnoreCase));
            if (textSectionIndex == -1) return false;

            IntPtr size = (IntPtr)(long)pereader.ImageSectionHeaders[textSectionIndex].VirtualSize;
            byte[] cleanSection = new byte[size.ToInt32()];
            Copy(ref fileBytes, pereader.ImageSectionHeaders[textSectionIndex].PointerToRawData, ref cleanSection, 0, pereader.ImageSectionHeaders[textSectionIndex].VirtualSize);

            IntPtr destination = Process.GetCurrentProcess().Modules
                .Cast<ProcessModule>()
                .First(x => DLLname.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).BaseAddress
                + pereader.ImageSectionHeaders[textSectionIndex].VirtualAddress;

            uint oldProtect = 0;
            if (!Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref destination, ref size, 0x40, ref oldProtect)) return false;

            try { Marshal.Copy(cleanSection, 0, destination, cleanSection.Length); }
            catch { return false; }

            uint tmp = 0;
            Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref destination, ref size, oldProtect, ref tmp);
            return true;
        }

        public static void EATUnhooker(string ModuleName)
        {
            IntPtr baseAddr = Process.GetCurrentProcess().Modules
                .Cast<ProcessModule>()
                .FirstOrDefault(x => ModuleName.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase))?.BaseAddress ?? IntPtr.Zero;

            if (baseAddr == IntPtr.Zero) return;

            byte[] moduleBytes = File.ReadAllBytes(Process.GetCurrentProcess().Modules
                .Cast<ProcessModule>()
                .First(x => ModuleName.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FileName);

            int peOffset = Marshal.ReadInt32(baseAddr + 60);
            long ntHeaderOffset = baseAddr.ToInt64() + peOffset + 24;
            bool is32Bit = Marshal.ReadInt16((IntPtr)(ntHeaderOffset)) == 0x10b;
            long exportTableOffset = ntHeaderOffset + (is32Bit ? 96 : 112);

            PEReader pereader = new PEReader(moduleBytes);
            int imageSize = (int)(pereader.Is32BitHeader ? pereader.OptionalHeader32.SizeOfImage : pereader.OptionalHeader64.SizeOfImage);
            int headerSize = (int)(pereader.Is32BitHeader ? pereader.OptionalHeader32.SizeOfHeaders : pereader.OptionalHeader64.SizeOfHeaders);

            IntPtr cleanImage = Marshal.AllocHGlobal(imageSize);
            Marshal.Copy(moduleBytes, 0, cleanImage, headerSize);
            foreach (var section in pereader.ImageSectionHeaders)
            {
                Marshal.Copy(moduleBytes, section.PointerToRawData, cleanImage + (int)section.VirtualAddress, section.SizeOfRawData);
            }

            int exportDirRVA = Marshal.ReadInt32((IntPtr)exportTableOffset);
            if (exportDirRVA == 0) return;

            IntPtr exportTableVA = baseAddr + exportDirRVA;
            IntPtr exportSize = (IntPtr)Marshal.ReadInt32((IntPtr)(baseAddr.ToInt64() + exportDirRVA + 16));

            uint oldProtect = 0;
            if (!Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref exportTableVA, ref exportSize, 0x04, ref oldProtect)) return;

            //... Logic to walk EAT and restore...
            Marshal.FreeHGlobal(cleanImage);
            dynamic tmp = 0U;
            Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref exportTableVA, ref exportSize, oldProtect, ref tmp);
        }

        public static void IATUnhooker(string ModuleName)
        {
            IntPtr baseAddr = Process.GetCurrentProcess().Modules
                .Cast<ProcessModule>()
                .FirstOrDefault(x => ModuleName.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase))?.BaseAddress ?? IntPtr.Zero;

            if (baseAddr == IntPtr.Zero) return;

            // ... Logic similar to EAT, with import descriptors and IAT entries checked and reset
        }
    }
}
