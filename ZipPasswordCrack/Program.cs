using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Ionic.Zip;
using Ionic.Zlib;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Collections.Concurrent;

namespace ZipPasswordCrack
{
    class Program
    {
        #region Static properties
        private static int currentPWLenght = 0;
        private static bool verboseOutput = false;
        private static bool silent = false;
        private static string charSpace = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./"; // Base64
        private static int maxPasswordLen = 10;
        private static int minPasswordLen = 5;
        #endregion

        static ConcurrentQueue<string> queue = new ConcurrentQueue<string>();

        #region Main

        static void Main(string[] args)
        {
#if DEBUG
            args = new string[] { "-v", "-d=refStrings.txt", "ZIP_FILE.ZIP", "OUT" };
#endif
            App(args);
        }
        static string file;
        static string outDir;
        static string inDict;
        static void App(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage ZipPasswordCrack [options] [zipfile] [output directory]");
                Console.WriteLine("Options");
                Console.WriteLine("  -v\t\tVerbose console ouput.");
                Console.WriteLine("  -s\t\tSilent. No console output.");
                Console.WriteLine("  -d=FILE\t\tDictionary file");
                Console.WriteLine("  Default\tSome console output.");
                return;
            }

            if (args.Length > 2)
            {
                for (int i = 0; i < (args.Length - 2); i++)
                {
                    if (args[i] == "-v")
                        verboseOutput = true;
                    else if (args[i] == "-s")
                        silent = true;
                    else if (args[i].StartsWith("-d"))
                        inDict = args[i].Split('=')[1];
                    else
                    {
                        Console.WriteLine("Error: unknown option '{0}'", args[i]);
                        return;
                    }
                }
            }

            file = args[args.Length - 2];
            outDir = args[args.Length - 1];
            if (verboseOutput)
            {
                Console.WriteLine("Input file is {0}.", file);
                Console.WriteLine("Output dir is {0}.", outDir);
            }

            CrackPassword();
        }
        #endregion

        #region Static methods
        static bool found = false;
        static int passwordsTested = 0;
        static string lastPwd = "";
        static object lockObj = new object();
        private static void CrackPassword()
        {
            if (!ZipFile.IsZipFile(file))
            {
                Console.WriteLine("Error: This is not a (valid) zipfile.");
                return;
            }

            var thdPasswordPump = new Thread(passwordsPump);
            thdPasswordPump.Start();

            Thread[] arrThreads = new Thread[4];
            for (int i = 0; i < arrThreads.Length; i++)
            {
                arrThreads[i] = new Thread(threadProcessPasswords);
                arrThreads[i].Start(i);
            }

            int lastCount = 0;
            while (!found)
            {
                Thread.Sleep(1000);

                int diff = passwordsTested - lastCount;
                lastCount = passwordsTested;

                Console.CursorLeft = 0;
                if (Console.CursorTop != 0)
                    Console.CursorTop--;

                Console.Write("Testing password length: {0} [{1} passwords/seconds].      \nCurrent password: {2}                 ", lastPwd.Length, diff, lastPwd);
            }
            Console.ReadKey();
        }
        private static void threadProcessPasswords(object obj)
        {
            while (!found)
            {
                string pass;
                if (queue.TryDequeue(out pass))
                {
                    DirectoryInfo di = new DirectoryInfo(outDir);
                    var d2 = di.CreateSubdirectory("thd" + obj.ToString());

                    lastPwd = pass;
                    tryOnePassword(pass, (int)obj);
                }
                else
                {
                    Thread.Sleep(10);
                }
            }

        }

        private static void tryOnePassword(string currentPassword, int threadID)
        {
            ZipFile zFile = new ZipFile(file);
            Interlocked.Increment(ref passwordsTested);
            zFile.Password = currentPassword;

            try
            {
                string dir = outDir + "/" + "thd" + threadID;
                zFile.ExtractAll(dir, ExtractExistingFileAction.OverwriteSilently);
                // Not thrown
                if (!silent)
                {
                    Console.WriteLine();
                }
                Console.WriteLine("Success! Password is {0}.", currentPassword);

                lock (lockObj)
                {
                    File.AppendText(string.Format("Success! Password is {0}\n", currentPassword));
                }

                found = true;
                return;
            }
            catch (BadPasswordException)
            {
                // Ignore this error
            }
            catch (BadCrcException)
            {
                // Ignore this error
            }
            catch (ZlibException)
            {
                // Ignore this error
            }
            catch (BadReadException)
            {
                // Ignore this error
            }
            catch (BadStateException)
            {
                // Ignore this error
            }
            catch (Exception e)
            {
                Console.WriteLine();
                Console.WriteLine("Error: {0}", e.ToString());
                Console.WriteLine("Can't continue.");

                found = true;
            }
            finally
            {
              //  // Remove tmp files, they will block decryption progress
              //  string[] files = Directory.GetFiles(outDir, "*.tmp");
              //  if (files.Count() > 0)
              //  {
              //      foreach (string f in files)
              //          File.Delete(f);
              //  }
            }
        }

        private static void passwordsPump(object obj)
        {
            StreamReader fs = null;
            if (inDict != null) fs = File.OpenText(inDict);

            while (!found)
            {
                if (fs == null)
                {
                    for (int pwdlen = minPasswordLen; pwdlen <= maxPasswordLen; pwdlen++)
                    {
                        foreach (string currentPassword in GetCombinations(getChars(charSpace), pwdlen))
                        {
                            if (found) return;

                            if (queue.Count > 100000) Thread.Sleep(10);
                            queue.Enqueue(currentPassword);
                        }
                    }
                }
                else
                {
                    string line;
                    while ((line = fs.ReadLine()) != null)
                    {
                        if (queue.Count > 100000) Thread.Sleep(10);
                        queue.Enqueue(line);
                    }
                }
            }
            if (fs != null) fs.Dispose();
        }

        private static IEnumerable<string> getChars(string Chars)
        {
            foreach (char c in Chars) yield return c.ToString();
        }
        //[MethodImpl(MethodImplOptions.AggressiveInlining)] // ??? DotNet Core ?
        public static IEnumerable<string> GetCombinations(IEnumerable<string> Items, int Length)
        {
            foreach (var c in Items)
            {
                if (Length == 1)
                {
                    yield return c.ToString();
                }
                else
                {
                    foreach (var i in GetCombinations(Items, Length - 1))
                    {
                        yield return string.Concat(c, i);
                    }
                }
            }
        }

        #endregion
    }
}