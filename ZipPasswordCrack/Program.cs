using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Ionic.Zip;
using Ionic.Zlib;
using System.Runtime.CompilerServices;

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
        #endregion

        #region Main

        static void Main(string[] args)
        {
#if DEBUG
            args = new string[] { "-v", "ZIP_FILE.ZIP", "OUT" };
            App(args);
#else
            App(args);
#endif
        }

        static void App(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage ZipPasswordCrack [options] [zipfile] [output directory]");
                Console.WriteLine("Options");
                Console.WriteLine("  -v\t\tVerbose console ouput.");
                Console.WriteLine("  -s\t\tSilent. No console output.");
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
                    else
                    {
                        Console.WriteLine("Error: unknown option '{0}'", args[i]);
                        return;
                    }
                }
            }

            string file = args[args.Length - 2];
            string outDir = args[args.Length - 1];
            if (verboseOutput)
            {
                Console.WriteLine("Input file is {0}.", file);
                Console.WriteLine("Output dir is {0}.", outDir);
            }

            CrackPassword(file, outDir);
        }
        #endregion

        #region Static methods
        private static void CrackPassword(string file, string outDir)
        {
            if (!ZipFile.IsZipFile(file))
            {
                Console.WriteLine("Error: This is not a (valid) zipfile.");
                return;
            }

            DateTime start = DateTime.Now;
            int currSecond = 60;
            double passwordsTested = 0;
            double oldPwPerS = 0;

            for (int pwdlen = 1; pwdlen <= maxPasswordLen; pwdlen++)
            {
                foreach (string currentPassword in GetCombinations(getChars(charSpace), pwdlen))
                {
                    ZipFile zFile = new ZipFile(file);
                    passwordsTested++;
                    zFile.Password = currentPassword;

                    try
                    {
                        DateTime current = DateTime.Now;
                        TimeSpan ts = current.Subtract(start);
                        double pwPerS = 0;
                        if (ts.Seconds > 0)
                            pwPerS = passwordsTested / ts.TotalSeconds;

                        // Test each password.
                        if (!silent)
                        {
                            if (!verboseOutput)
                            {
                                if ((currentPWLenght != currentPassword.Length) || (oldPwPerS != pwPerS))
                                {
                                    if (currSecond != DateTime.Now.Second)
                                    {
                                        currSecond = DateTime.Now.Second;
                                        currentPWLenght = currentPassword.Length;
                                        oldPwPerS = pwPerS;
                                        Console.CursorLeft = 0;
                                        if (pwPerS > 0)
                                            Console.Write("Testing password length: {0} [{1} passwords/seconds]", currentPWLenght, (int)pwPerS);
                                        else
                                            Console.Write("Testing password length: {0}", currentPWLenght);
                                    }
                                }
                            }
                            else
                            {
                                if (currSecond != DateTime.Now.Second)
                                {
                                    currSecond = DateTime.Now.Second;
                                    currentPWLenght = currentPassword.Length;
                                    oldPwPerS = pwPerS;
                                    Console.CursorLeft = 0;
                                    if (Console.CursorTop != 0)
                                        Console.CursorTop--;

                                    if (pwPerS > 0)
                                        Console.Write("Testing password length: {0} [{1} passwords/seconds].\nCurrent password: {2}", currentPWLenght, (int)pwPerS, currentPassword);
                                    else
                                        Console.Write("Testing password length: {0}.\nCurrent password: {1}", currentPWLenght, currentPassword);
                                }
                            }
                        }

                        zFile.ExtractAll(outDir, ExtractExistingFileAction.OverwriteSilently);
                        // Not thrown
                        if (!silent)
                        {
                            Console.WriteLine();
                        }
                        Console.WriteLine("Success! Password is {0}.", currentPassword);
                        break;

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
                        break;
                    }
                    finally
                    {
                        // Remove tmp files, they will block decryption progress
                        string[] files = Directory.GetFiles(outDir, "*.tmp");
                        if (files.Count() > 0)
                        {
                            foreach (string f in files)
                                File.Delete(f);
                        }
                    }
                }
            }
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