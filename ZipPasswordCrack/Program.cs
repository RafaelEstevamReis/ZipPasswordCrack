using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Ionic.Zip;
using Ionic.Zlib;

namespace ZipPasswordCrack
{
    class Program
    {
        #region Static properties
        private static string currentPassword = string.Empty;
        private static int currentPWLenght = 0;
        private static bool verboseOutput = false;
        private static bool silent = false;
        #endregion

        #region Main
        static void Main(string[] args)
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
            double passwordsTested = 0;
            double oldPwPerS = 0;
            bool testing = true;
            while (testing)
            {
                ZipFile zFile = new ZipFile(file);
                GetNextPassword();
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
                                currentPWLenght = currentPassword.Length;
                                oldPwPerS = pwPerS;
                                Console.CursorLeft = 0;
                                if (pwPerS > 0)
                                    Console.Write("Testing password length: {0} [{1} passwords/seconds]", currentPWLenght, (int)pwPerS);
                                else
                                    Console.Write("Testing password length: {0}", currentPWLenght);
                            }
                        }
                        else
                        {
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

                    zFile.ExtractAll(outDir, ExtractExistingFileAction.OverwriteSilently);
                    testing = false;

                    if (!silent)
                    {
                        Console.WriteLine();
                    }
                    Console.WriteLine("Success! Password is {0}.", currentPassword);
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
                    testing = false;
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

        private static void GetNextPassword()
        {
            currentPassword = IncreasePassword(currentPassword);
        }

        private static string IncreasePassword(string pw)
        {
            if (string.IsNullOrEmpty(pw))
                return "!";

            byte x = (byte)pw[pw.Length - 1];
            pw = pw.Remove(pw.Length - 1);

            if (x != byte.MaxValue)
            {
                x++;
                pw += (char)x;
            }
            else
            {
                pw = IncreasePassword(pw);
                pw += "!";
            }

            return pw;
        }
        #endregion
    }
}
