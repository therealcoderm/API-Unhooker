using apiunhooker;
using System;

namespace ApiUnhooker
{
    public class APIUnhooker
    {
        public static void Start()
        {
            string[] dllsToUnhook = new string[]
            {
                "ntdll.dll",
                "kernel32.dll",
                "kernelbase.dll",
                "advapi32.dll",
                "ole32.dll",
                "shell32.dll",
                "comdlg32.dll",
                "gdi32.dll",
                "version.dll",
                "secur32.dll",
                "crypt32.dll",
                "shlwapi.dll",
                "dnsapi.dll",
                "netapi32.dll",
                "dbghelp.dll",
                "mpr.dll"
            };

            foreach (string dll in dllsToUnhook)
            {
                Unhooker.JMPUnhooker(dll);
                Unhooker.EATUnhooker(dll);
                if (!dll.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase))
                {
                    Unhooker.IATUnhooker(dll);
                }
            }
        }
    }
}