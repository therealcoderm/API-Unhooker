using System;
using System.IO;
using System.Runtime.InteropServices;

namespace apiunhooker
{
    public class PEReader
    {
        public PEReader(string filePath)
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            using (BinaryReader br = new BinaryReader(fs))
            {
                dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(br);
                fs.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
                br.ReadUInt32();
                fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(br);

                if (Is32BitHeader)
                    optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(br);
                else
                    optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(br);

                imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
                for (int i = 0; i < imageSectionHeaders.Length; i++)
                    imageSectionHeaders[i] = FromBinaryReader<IMAGE_SECTION_HEADER>(br);

                rawbytes = File.ReadAllBytes(filePath);
            }
        }

        public PEReader(byte[] fileBytes)
        {
            using (MemoryStream ms = new MemoryStream(fileBytes))
            using (BinaryReader br = new BinaryReader(ms))
            {
                dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(br);
                ms.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
                br.ReadUInt32();
                fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(br);

                if (Is32BitHeader)
                    optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(br);
                else
                    optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(br);

                imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
                for (int i = 0; i < imageSectionHeaders.Length; i++)
                    imageSectionHeaders[i] = FromBinaryReader<IMAGE_SECTION_HEADER>(br);

                rawbytes = fileBytes;
            }
        }

        public static T FromBinaryReader<T>(BinaryReader reader)
        {
            byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());
            handle.Free();
            return theStructure;
        }

        public bool Is32BitHeader => (fileHeader.Characteristics & 0x0100) == 0x0100;

        public IMAGE_FILE_HEADER FileHeader => fileHeader;
        public IMAGE_OPTIONAL_HEADER32 OptionalHeader32 => optionalHeader32;
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader64 => optionalHeader64;
        public IMAGE_SECTION_HEADER[] ImageSectionHeaders => imageSectionHeaders;
        public byte[] RawBytes => rawbytes;

        private IMAGE_DOS_HEADER dosHeader;
        private IMAGE_FILE_HEADER fileHeader;
        private IMAGE_OPTIONAL_HEADER32 optionalHeader32;
        private IMAGE_OPTIONAL_HEADER64 optionalHeader64;
        private IMAGE_SECTION_HEADER[] imageSectionHeaders;
        private byte[] rawbytes;

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            public ushort e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc, e_ss, e_sp,
                          e_csum, e_ip, e_cs, e_lfarlc, e_ovno, e_res_0, e_res_1, e_res_2, e_res_3,
                          e_oemid, e_oeminfo, e_res2_0, e_res2_1, e_res2_2, e_res2_3, e_res2_4,
                          e_res2_5, e_res2_6, e_res2_7, e_res2_8, e_res2_9;
            public uint e_lfanew;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            public ushort Magic;
            public byte MajorLinkerVersion, MinorLinkerVersion;
            public uint SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData, AddressOfEntryPoint,
                         BaseOfCode, BaseOfData, ImageBase, SectionAlignment, FileAlignment,
                         Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum, LoaderFlags,
                         NumberOfRvaAndSizes;
            public ushort MajorOperatingSystemVersion, MinorOperatingSystemVersion,
                          MajorImageVersion, MinorImageVersion,
                          MajorSubsystemVersion, MinorSubsystemVersion, Subsystem, DllCharacteristics;
            public uint SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
            public IMAGE_DATA_DIRECTORY ExportTable, ImportTable, ResourceTable, ExceptionTable,
                                        CertificateTable, BaseRelocationTable, Debug, Architecture,
                                        GlobalPtr, TLSTable, LoadConfigTable, BoundImport,
                                        IAT, DelayImportDescriptor, CLRRuntimeHeader, Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public ushort Magic;
            public byte MajorLinkerVersion, MinorLinkerVersion;
            public uint SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData, AddressOfEntryPoint,
                         BaseOfCode, SectionAlignment, FileAlignment, Win32VersionValue, SizeOfImage,
                         SizeOfHeaders, CheckSum, LoaderFlags, NumberOfRvaAndSizes;
            public ushort MajorOperatingSystemVersion, MinorOperatingSystemVersion,
                          MajorImageVersion, MinorImageVersion,
                          MajorSubsystemVersion, MinorSubsystemVersion, Subsystem, DllCharacteristics;
            public ulong ImageBase, SizeOfStackReserve, SizeOfStackCommit,
                         SizeOfHeapReserve, SizeOfHeapCommit;
            public IMAGE_DATA_DIRECTORY ExportTable, ImportTable, ResourceTable, ExceptionTable,
                                        CertificateTable, BaseRelocationTable, Debug, Architecture,
                                        GlobalPtr, TLSTable, LoadConfigTable, BoundImport,
                                        IAT, DelayImportDescriptor, CLRRuntimeHeader, Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Name;
            public uint VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData,
                         PointerToRelocations, PointerToLinenumbers;
            public ushort NumberOfRelocations, NumberOfLinenumbers;
            public uint Characteristics;
        }
    }
}
