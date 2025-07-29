using System;

namespace SharpDecryptPwd.Helpers
{
    class Writer
    {
        public static void Line(string log)
        {
            Console.WriteLine(log);
        }

        public static void Log(string log)
        {
            Console.WriteLine($"[+] {log}");
        }

        public static void Out(string key, string value)
        {
            Console.WriteLine("    [>] {0,-15}: {1}", key, value);
        }

        public static void Warnning(string log)
        {
            Console.WriteLine($"[!] Warning: {log}");
        }

        public static void Failed(string log)
        {
            Console.WriteLine($"[!] Failed: \r\n{log}");
        }

        public static void ErrorLine(string log)
        {
            Console.WriteLine($"[!] Error: \r\n{log}");
        }

        public static void Error(string log)
        {
            Console.WriteLine($"[!] Error: \r\n{log}");
            Environment.Exit(0);
        }
    }
}
