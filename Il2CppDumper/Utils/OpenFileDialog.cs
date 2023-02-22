using System;
using static Il2CppDumper.FileDialogNative;

namespace Il2CppDumper
{
    public class OpenFileDialog
    {
        public string Title { get; set; }
        public string Filter { get; set; }
        public string FileName { get; set; }

        public bool ShowDialog()
        {
            var dialog = (IFileDialog)(new FileOpenDialogRCW());
            dialog.GetOptions(out var options);
            options |= FOS.FOS_FORCEFILESYSTEM | FOS.FOS_NOVALIDATE | FOS.FOS_DONTADDTORECENT;
            dialog.SetOptions(options);
            if (!string.IsNullOrEmpty(Title))
            {
                dialog.SetTitle(Title);
            }
            if (!string.IsNullOrEmpty(Filter))
            {
                string[] filterElements = Filter.Split(new char[] { '|' });
                COMDLG_FILTERSPEC[] filter = new COMDLG_FILTERSPEC[filterElements.Length / 2];
                for (int x = 0; x < filterElements.Length; x += 2)
                {
                    filter[x / 2].pszName = filterElements[x];
                    filter[x / 2].pszSpec = filterElements[x + 1];
                }
                dialog.SetFileTypes((uint)filter.Length, filter);
            }
            if (dialog.Show(IntPtr.Zero) == 0)
            {
                dialog.GetResult(out var shellItem);
                shellItem.GetDisplayName(SIGDN.SIGDN_FILESYSPATH, out var ppszName);
                FileName = ppszName;
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}