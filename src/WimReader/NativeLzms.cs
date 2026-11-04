// Raw WIM LZMS blocks use the Windows Compression API in block mode.
// COMPRESS_RAW and COMPRESS_ALGORITHM_LZMS are defined in compressapi.h.
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

namespace DiscUtils.Wim;

internal static class NativeLzms
{
    private const uint CompressRaw = 1u << 29;
    private const uint AlgorithmLzms = 5;

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("cabinet.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDecompressor(uint algorithm, IntPtr allocationRoutines, out IntPtr handle);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("cabinet.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Decompress(IntPtr handle, byte[] input, nuint inputSize,
        byte[] output, nuint outputSize, out nuint written);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("cabinet.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseDecompressor(IntPtr handle);

    internal static byte[] Decode(byte[] input, int outputSize)
    {
        if (outputSize < 0) throw new ArgumentOutOfRangeException(nameof(outputSize));
        if (input.Length == outputSize) return input;
        if (!CreateDecompressor(CompressRaw | AlgorithmLzms, IntPtr.Zero, out var handle))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not initialize LZMS decompression.");
        try
        {
            byte[] output = new byte[outputSize];
            if (!Decompress(handle, input, (nuint)input.Length, output, (nuint)output.Length, out var written))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not decompress an LZMS WIM block.");
            if (written != (nuint)outputSize) throw new InvalidDataException("LZMS block length does not match its WIM metadata.");
            return output;
        }
        finally { CloseDecompressor(handle); }
    }
}
