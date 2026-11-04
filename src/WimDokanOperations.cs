using DiscUtils;
using DiscUtils.MountDokan;
using DiscUtils.Wim;
using DokanNet;
using LTRData.Extensions.Native.Memory;

// The drive's Dokan operations: LTRData's adapter, except for searches with a DOS star.
// FindFirstFile sends "*." as "<" and "*.cat" as "<.cat" (traced in the VM, 2026-11-04);
// the adapter turns every '<' into '*', so "dir *." listed names with an extension too.
// Re-implementing only this member of the interface leaves every other one to the adapter.
internal sealed class WimDokanOperations(IFileSystem fileSystem, DokanDiscUtilsOptions options)
    : DokanDiscUtils(fileSystem, options), IDokanOperations2
{
    NtStatus IDokanOperations2.FindFilesWithPattern(ReadOnlyNativeMemory<char> fileName, ReadOnlyNativeMemory<char> searchPattern,
        out IEnumerable<FindFileInformation> files, ref DokanFileInfo info)
    {
        string pattern = searchPattern.ToString();
        if (!pattern.Contains('<')) return FindFilesWithPattern(fileName, searchPattern, out files, ref info);
        // The whole folder, matched the way NTFS matches (WildcardFilter's DOS-pattern path).
        NtStatus status = FindFiles(fileName, out var all, ref info);
        files = status == NtStatus.Success ? all.Where(f => WildcardFilter.Matches(f.FileName.ToString(), pattern)) : all;
        return status;
    }
}
