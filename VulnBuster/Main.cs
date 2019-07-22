using System;
using System.Runtime.InteropServices;
using System.Threading;


namespace VulnBuster
{
    public class VulnBuster
    {
        public VulnBuster() { Console.WriteLine("I am a basic COM Object"); }


        [ComRegisterFunction] //This executes if registration is successful
        public static void RegisterClass(string key)
        {
            Console.Clear(); //Clears default ReGasm output on command prompt

            int milliseconds = 2000;
            Thread.Sleep(milliseconds);
            while (true)
            {
                Console.WriteLine("Key in the corresponding number:");
                Console.WriteLine("1. Application CVE Reporting");
                Console.WriteLine("2. LOLBin Detection");
                string input = Console.ReadLine();
                if (input == "1") //Key in 1 to proceed to CVE Reporting function
                {
                    CVEGenerator.cveGeneratorMain(); //Function to generate CVE Text Reports
                }

                else if (input == "2") //Key in 2 to proceed to LOLBin detection function
                {
                    LOL.getLOLinfo();
                }
            }

        }

        [ComUnregisterFunction] //This executes if registration fails
        public static void UnRegisterClass(string key)
        {
            Console.Clear(); //Clears default ReGasm output on command prompt
            Logo.DisplayLogo(); //VulnBuster logo displayed
            int milliseconds = 2000;
            Thread.Sleep(milliseconds);
            while (true)
            {
                Console.WriteLine("Key in the corresponding number:");
                Console.WriteLine("1. Application CVE Reporting");
                Console.WriteLine("2. LOLBin Detection");
                string input = Console.ReadLine();
                if (input == "1") //Key in 1 to proceed to CVE Reporting function
                {
                    CVEGenerator.cveGeneratorMain(); //Function to generate CVE Text Reports
                }

                else if (input == "2") //Key in 2 to proceed to LOLBin detection function
                {
                    LOL.getLOLinfo();
                }
            }
        }
    }
}