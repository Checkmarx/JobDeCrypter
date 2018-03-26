/*
Copyright(c) 2017 Checkmarx

Author: João Pena Gil (Jack64)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.
*/
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;

namespace jobCryptor
{
    class Program
    {
        /// <summary>
        /// Program entry point
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            Console.WriteLine("jobCrypter Password Cracker");

            //Require elevated privileges
            if (!isAdmin())
            {
                ProcessStartInfo startInfo = new ProcessStartInfo(AppDomain.CurrentDomain.FriendlyName);
                startInfo.Verb = "runas";
                System.Diagnostics.Process.Start(startInfo);
                Environment.Exit(0);
            }

            Console.WriteLine("[*] Searching for the first encrypted file's timestamp...");

            FileInfo targetPNG = new FileInfo("C:\\ProgramData\\Microsoft\\User Account Pictures\\user.png.css");
            var timestamp = EncryptedFileFinder.getFirstEncryptedFile(ref targetPNG);

            Console.WriteLine("[+] First encrypted file created at: {0}", timestamp.ToString());

            //Get last reboot time to calculate approximation of Environment.TickCount
            Console.WriteLine("[*] Getting last boot time before encryption...");
            DateTime lastReboot = EncryptedFileFinder.getLastReboot(timestamp);

            if (lastReboot == default(DateTime))
            {
                Console.WriteLine("[!] Proceeding with no knowledge of boot time.");
            }
            else
            {
                Console.WriteLine("[+] Last boot time before encryption: {0}", lastReboot.ToString());
            }

            EncryptedFileFinder.CalculatePassword(args, timestamp, lastReboot, targetPNG);

        }


        /// <summary>
        /// Determines whether the process has elevated privileges
        /// </summary>
        /// <returns></returns>
        private static bool isAdmin()
        {
            bool isElevated;
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                isElevated = principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            return isElevated;
        }

        private static void PrintUsage()
        {
            Console.WriteLine($"Usage: {AppDomain.CurrentDomain.FriendlyName}");
            Console.WriteLine();
            Console.Read();
            Environment.Exit(1);
        }
    }
}
