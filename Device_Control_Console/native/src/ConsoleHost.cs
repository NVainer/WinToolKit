// Keeps the window open when the program was started by double-clicking it.
//
// A console program launched from Explorer gets a console of its own, and
// Windows destroys that console the moment the process exits -- so any output,
// including the reason it failed, flashes past unreadably.  Launched from an
// existing terminal there is nothing to fix, and pausing would be an
// annoyance, so the two cases have to be told apart.
//
// GetConsoleProcessList reports how many processes are attached to this
// console.  Exactly one means nobody else is sharing it: we own it, and it
// dies with us.
using System;
using System.Runtime.InteropServices;

namespace DeviceControlConsole
{
    public static class ConsoleHost
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint GetConsoleProcessList(uint[] processList, uint count);

        private static bool? _ownsConsole;

        /// <summary>True when this process is the only one on its console.</summary>
        public static bool OwnsConsoleWindow()
        {
            if (_ownsConsole.HasValue) return _ownsConsole.Value;
            try
            {
                uint[] buffer = new uint[8];
                uint count = GetConsoleProcessList(buffer, (uint)buffer.Length);
                _ownsConsole = count == 1;
            }
            catch (Exception)
            {
                _ownsConsole = false;
            }
            return _ownsConsole.Value;
        }

        /// <summary>Waits for a keypress, but only if the window is about to vanish.</summary>
        public static void PauseIfLaunchedFromExplorer(string reason)
        {
            if (!OwnsConsoleWindow()) return;
            Console.WriteLine();
            if (!string.IsNullOrEmpty(reason)) Console.WriteLine(reason);
            Console.WriteLine("Press any key to close this window...");
            try { Console.ReadKey(true); }
            catch (InvalidOperationException) { Console.ReadLine(); }  // no key device
        }
    }
}
