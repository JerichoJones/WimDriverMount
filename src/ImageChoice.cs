using System.Runtime.InteropServices;

// Asks which image of a multi-image WIM to mount, for the right-click Mount.
// A Windows task dialog with one button per image: in-box, and needs only the
// common-controls line in app.manifest.
internal static class ImageChoice
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct Button { public int Id; public IntPtr Text; }

    // commctrl.h declares the task dialog structures byte-packed (pshpack1.h).
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct Config
    {
        public uint Size;
        public IntPtr Parent, Instance;
        public int Flags, CommonButtons;
        public IntPtr Title, MainIcon, MainInstruction, Content;
        public uint ButtonCount;
        public IntPtr Buttons;
        public int DefaultButton;
        public uint RadioButtonCount;
        public IntPtr RadioButtons;
        public int DefaultRadioButton;
        public IntPtr Verification, Expanded, ExpandedControl, CollapsedControl, FooterIcon, Footer, Callback, CallbackData;
        public uint Width;
    }

    [DllImport("comctl32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int TaskDialogIndirect(ref Config config, out int button, out int radioButton, out int verification);

    private const int FirstImage = 1000;

    // The 1-based image index, or null if the user cancelled.
    internal static int? Ask(string wim, IReadOnlyList<string?> names)
    {
        var strings = new List<IntPtr>();
        IntPtr Text(string value) { IntPtr p = Marshal.StringToHGlobalUni(value); strings.Add(p); return p; }
        IntPtr buttons = Marshal.AllocHGlobal(Marshal.SizeOf<Button>() * names.Count);
        try
        {
            for (int i = 0; i < names.Count; i++)
            {
                string name = SafeText.Message(names[i] ?? "");
                if (name.Length > 120) name = name[..117] + "...";
                Marshal.StructureToPtr(new Button { Id = FirstImage + i, Text = Text(name.Length == 0 ? $"Image {i + 1}" : $"{i + 1}. {name}") },
                    buttons + i * Marshal.SizeOf<Button>(), false);
            }
            const int AllowCancel = 0x8, CommandLinks = 0x10, CancelButton = 0x8;
            var config = new Config
            {
                Size = (uint)Marshal.SizeOf<Config>(),
                Flags = AllowCancel | CommandLinks,
                CommonButtons = CancelButton,
                Title = Text("WIM Driver Mount"),
                MainInstruction = Text("Which image do you want to mount?"),
                Content = Text($"{SafeText.Path(Path.GetFileName(wim))} holds {names.Count} images. The one you choose is mounted read-only at the highest free drive letter."),
                ButtonCount = (uint)names.Count,
                Buttons = buttons,
                DefaultButton = FirstImage,
            };
            int result = TaskDialogIndirect(ref config, out int chosen, out _, out _);
            if (result != 0) throw new IOException($"The image choice could not be shown (error 0x{result:X8}). Mount it from a console with --index.");
            return chosen >= FirstImage && chosen < FirstImage + names.Count ? chosen - FirstImage + 1 : null;
        }
        finally
        {
            Marshal.FreeHGlobal(buttons);
            foreach (IntPtr p in strings) Marshal.FreeHGlobal(p);
        }
    }
}
