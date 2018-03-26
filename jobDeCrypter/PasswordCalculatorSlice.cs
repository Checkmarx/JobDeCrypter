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

namespace jobCryptor
{
    /// <summary>
    /// Slice of work to be executed in threaded mode
    /// </summary>
    public class PasswordCalculatorSlice
    {

        string filename;
        int start;
        int threadnum;
        double offset;
        int threads;

        /// <summary>
        /// Instantiates the object
        /// </summary>
        /// <param name="threadnum"></param>
        /// <param name="filename"></param>
        /// <param name="start"></param>
        /// <param name="offset"></param>
        /// <param name="threads"></param>
        public PasswordCalculatorSlice(int threadnum, string filename, int start, double offset, int threads)
        {
            this.threadnum = threadnum;
            this.filename = filename;
            this.start = start;
            this.offset = offset;
            this.threads = threads;
        }

        /// <summary>
        /// Runs the slice of work, calculating a password and then attempting decryption
        /// </summary>
        public void runSlice()
        {
            for (int i = 0;  i < offset; i++)
            {
                string password = passwordFromTickCount(start + i);
                EncryptedFileFinder.Decode_File(filename, password);
            }
        }
        
        /// <summary>
        /// Creates a new password with a fixed seed for Random()
        /// </summary>
        /// <param name="tickCount"></param>
        /// <returns></returns>
        static string passwordFromTickCount(int tickCount)
        {
            return CreateRandomPassword(20, tickCount);
        }

        /// <summary>
        /// CreateRandomPassword(int PasswordLength) with user-selected seed value to calculate password candidates
        /// </summary>
        /// <param name="PasswordLength"></param>
        /// <param name="tickCount"></param>
        /// <returns></returns>
        public static string CreateRandomPassword(int PasswordLength, int tickCount)
        {
            string text = "0123456789";
            Random random = new Random(tickCount);
            checked
            {
                char[] array = new char[PasswordLength - 1 + 1];
                int num = PasswordLength - 1;
                int num2 = 0;
                while (true)
                {
                    if (num2 > num)
                    {
                        break;
                    }
                    array[num2] = text[(int)Math.Round(Fix(unchecked((double)text.Length * random.NextDouble())))];
                    num2++;
                }
                return new string(array);
            }
        }

        /// <summary>
        /// Fix(double number) as seen in Conversion.Fix on jobCrypter
        /// </summary>
        /// <param name="Number"></param>
        /// <returns></returns>
        public static double Fix(double Number)
        {
            if (Number >= 0.0)
            {
                return Math.Floor(Number);
            }
            return -Math.Floor(-Number);
        }
    }

}
