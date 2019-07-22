using Microsoft.Win32;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Text;
using System.Threading;

namespace VulnBuster
{
    public class CVEGenerator
    {

        //Code portion for the structure of the json file as C# classes
        public class VendorData
        {
            public string vendor_name { get; set; }
            public Product product { get; set; }
        }

        public class Product
        {
            public List<ProductData> product_data { get; set; }
        }

        public class ProductData
        {
            public string product_name { get; set; }
            public Versionz version { get; set; }
        }

        public class Versionz
        {
            public List<VersionData> version_data { get; set; }
        }

        public class VersionData
        {
            public string version_value { get; set; }
            public string version_affected { get; set; }
        }
        public class CVEDataMeta
        {
            public string ID { get; set; }
            public string ASSIGNER { get; set; }
        }

        public class Vendor
        {
            public List<VendorData> vendor_data { get; set; }
        }

        public class Affects
        {
            public Vendor vendor { get; set; }
        }

        public class ProblemtypeData
        {
            public List<object> description { get; set; }
        }

        public class Problemtype
        {
            public List<ProblemtypeData> problemtype_data { get; set; }
        }

        public class ReferenceData
        {
            public string url { get; set; }
            public string name { get; set; }
            public string refsource { get; set; }
            public List<object> tags { get; set; }
        }

        public class References
        {
            public List<ReferenceData> reference_data { get; set; }
        }

        public class DescriptionData
        {
            public string lang { get; set; }
            public string value { get; set; }
        }

        public class Description
        {
            public List<DescriptionData> description_data { get; set; }
        }

        public class Cve
        {
            public string data_type { get; set; }
            public string data_format { get; set; }
            public string data_version { get; set; }
            public CVEDataMeta CVE_data_meta { get; set; }
            public Affects affects { get; set; }
            public Problemtype problemtype { get; set; }
            public References references { get; set; }
            public Description description { get; set; }
        }

        public class Configurations
        {
            public string CVE_data_version { get; set; }
            public List<object> nodes { get; set; }
        }

        public class CvssV3
        {
            public string version { get; set; }
            public string vectorString { get; set; }
            public string attackVector { get; set; }
            public string attackComplexity { get; set; }
            public string privilegesRequired { get; set; }
            public string userInteraction { get; set; }
            public string scope { get; set; }
            public string confidentialityImpact { get; set; }
            public string integrityImpact { get; set; }
            public string availabilityImpact { get; set; }
            public double baseScore { get; set; }
            public string baseSeverity { get; set; }
        }

        public class BaseMetricV3
        {
            public CvssV3 cvssV3 { get; set; }
            public double exploitabilityScore { get; set; }
            public double impactScore { get; set; }
        }

        public class CvssV2
        {
            public string version { get; set; }
            public string vectorString { get; set; }
            public string accessVector { get; set; }
            public string accessComplexity { get; set; }
            public string authentication { get; set; }
            public string confidentialityImpact { get; set; }
            public string integrityImpact { get; set; }
            public string availabilityImpact { get; set; }
            public double baseScore { get; set; }
        }

        public class BaseMetricV2
        {
            public CvssV2 cvssV2 { get; set; }
            public string severity { get; set; }
            public double exploitabilityScore { get; set; }
            public double impactScore { get; set; }
            public bool acInsufInfo { get; set; }
            public bool obtainAllPrivilege { get; set; }
            public bool obtainUserPrivilege { get; set; }
            public bool obtainOtherPrivilege { get; set; }
            public bool userInteractionRequired { get; set; }
        }

        public class Impact
        {
            public BaseMetricV3 baseMetricV3 { get; set; }
            public BaseMetricV2 baseMetricV2 { get; set; }
        }

        public class CVEItem
        {
            public Cve cve { get; set; }
            public Configurations configurations { get; set; }
            public Impact impact { get; set; }
            public string publishedDate { get; set; }
            public string lastModifiedDate { get; set; }
        }

        public class RootObject
        {
            public string CVE_data_type { get; set; }
            public string CVE_data_format { get; set; }
            public string CVE_data_version { get; set; }
            public string CVE_data_numberOfCVEs { get; set; }
            public string CVE_data_timestamp { get; set; }
            public List<CVEItem> CVE_Items { get; set; }
        }

        public static void cveGeneratorMain()
        {
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            List<RegistryKey> appKeys = new List<RegistryKey>();

            var HKLM32 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
            var HKLM64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            string subKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"; //Location in registry that shows all installed applications in sytem
            var key64 = HKLM64.OpenSubKey(subKey);

            RegistryKey uninstallKey64 = HKLM64.OpenSubKey(subKey);
            RegistryKey uninstallKey32 = HKLM32.OpenSubKey(subKey);
            string[] allApplications64 = uninstallKey64.GetSubKeyNames(); //Array of 64 bit applications installed in system
            string[] allApplications32 = uninstallKey32.GetSubKeyNames(); //Array of 32 bit applications installed in system

            //Prompts user if they wish to download the CVE JSON files online, which will be needed to be downloaded at least once for the function to do anything
            Console.WriteLine(
                "Would you like to download the latest vulnerability databases? Key in 'Y' to download. Note that the program will not work if you have not download these files at least once:");
            string option = Console.ReadLine();

            if (option.ToLower() == "y") // If he wishes to download the CVE JSON files.....
            {
                //Checks if system has internet access. Won't be able to download CVE JSON files otherwise
                if (!CVEGenerator.checkForInternetConnection())
                {
                    Console.WriteLine("\n#######################################");
                    Console.WriteLine("You do not have internet access to download the database. Quit to try again.");
                    Console.WriteLine("#######################################\n");
                    Console.WriteLine("Skipping download........\nPress enter to continue");
                    Console.ReadLine();
                }
                else
                {
                    CVEGenerator.dlCVEDB(); //Downloads the CVE files online
                }

            }
            Console.WriteLine("Detecting all installed applications.....");
            //Short pause
            int milliseconds = 2000;
            Thread.Sleep(milliseconds);
            Console.WriteLine("\n#######################################");
            Console.WriteLine("List of installed applications:");
            Console.WriteLine("#######################################\n");
            String windowsVer = CVEGenerator.checkWindowsVersion(); //Checks your current Windows Version 
            String windowsOs = CVEGenerator.checkWindowsOS(); //Checks your current Windows OS (e.g 10, 8.1, XP)

            //Displays all applications installed and their versions
            if (allApplications64.Length != 0)
            {
                foreach (string applicationSubKeyName in allApplications64)
                {
                    RegistryKey appKey = HKLM64.OpenSubKey(subKey + "\\" + applicationSubKeyName);

                    appKeys.Add(appKey);
                    string appName = (string)appKey.GetValue("DisplayName");
                    string appVersion = (string)appKey.GetValue("DisplayVersion");

                    if (String.IsNullOrEmpty(appName))
                        continue;
                    Console.WriteLine("Application Name: " + appName + "\nVersion: " + appVersion + "\n");
                }

                if (allApplications32.Length != 0)
                {
                    foreach (string applicationSubKeyName in allApplications32)
                    {
                        RegistryKey appKey = HKLM32.OpenSubKey(subKey + "\\" + applicationSubKeyName);

                        appKeys.Add(appKey);
                        string appName = (string)appKey.GetValue("DisplayName");
                        string appVersion = (string)appKey.GetValue("DisplayVersion");

                        if (String.IsNullOrEmpty(appName))
                            continue;
                        Console.WriteLine("Application Name: " + appName + "\nVersion: " + appVersion + "\n");
                    }

                }

                Console.WriteLine("#######################################\n");
                bool isSearching = true;
                while (isSearching == true)
                {
                    Console.WriteLine("Key in the corresponding number:");
                    Console.WriteLine("1. Generate report for all applications installed");
                    Console.WriteLine("2. Manually select applications");
                    Console.WriteLine("3. Quit");
                    string input1 = Console.ReadLine();

                    //Quits to the previous menu
                    if (input1 == "3")
                    {
                        isSearching = false;
                        break;
                    }

                    //Generates report for all applications installed
                    if (input1 == "1")
                    {
                        String dateTimeString = DateTime.Now.ToString("MMddyyyyHHmmss"); // Current datetime as string

                        CVEGenerator.generateTextReport(windowsOs, windowsVer, dateTimeString); //Generates the CVE Text report for Windows 10
                        foreach (var appkey in appKeys)
                        {
                            try
                            {
                                CVEGenerator.generateTextReport((string)appkey.GetValue("DisplayName"), (string)appkey.GetValue("DisplayVersion"), dateTimeString); //Generates the CVE Text report for the rest of the applications
                            }
                            catch (Exception e)
                            {

                            }
                        }
                    }

                    //User has to manually key in all applications that he wishes to generate CVE reports for
                    else if (input1 == "2")
                    {
                        bool isFound = false;
                        bool keepAddingPrograms = true;
                        List<string> programsToCheck = new List<string>();
                        List<string> programVersions = new List<string>();
                        while (keepAddingPrograms == true)
                        {
                            Console.WriteLine(
                                "\nEnter application names installed in your system that you would like to see the vulnerabilities for: (Key in 'S' to stop adding applications, 'X' to quit this mode)");
                            string input = Console.ReadLine();

                            // This will commence the CVE generation process
                            if (input.ToLower() == "s")
                            {
                                keepAddingPrograms = false;
                                break;
                            }

                            // This will bring the user to the previous menu
                            else if (input.ToLower() == "x")
                            {
                                isSearching = false;
                                break;
                            }

                            //Loops through each installed application to detect the application you are searching for
                            foreach (var appkey in appKeys)
                            {
                                string appName = (string)appkey.GetValue("DisplayName");
                                if (appName == null)
                                {
                                    continue;
                                }

                                string appVersion = (string)appkey.GetValue("DisplayVersion");
                                //If application that user wants to search for is Windows OS
                                if (input.ToLower().Contains(windowsOs.ToLower()) ||
                                    windowsOs.ToLower().Contains(input.ToLower()))
                                {
                                    //If windows OS is installed
                                    if (windowsVer != "")
                                    {
                                        isFound = true;
                                        appName = windowsOs;
                                        appVersion = windowsVer;
                                        Console.WriteLine("\nApplication found.");
                                        Console.WriteLine("Application Name: " + appName);
                                        Console.WriteLine("Version: " + appVersion);
                                        Console.WriteLine("Is this the application? Enter 'Y' to continue:");
                                        string choice = Console.ReadLine();

                                        //If the user does not think that this is the app he/she is searching for
                                        if (choice.ToLower() != "y")
                                        {
                                            Console.WriteLine("Aborted. Searching other apps.....");
                                            continue;
                                        }
                                        else
                                        {
                                            isFound = true;
                                        }
                                    }
                                }

                                //Else if your application is found (not windows)
                                else if (appName.ToLower().Contains(input.ToLower()) ||
                                         input.ToLower().Contains(appName.ToLower()))
                                {
                                    Console.WriteLine("\nApplication match found.");
                                    Console.WriteLine("Application Name: " + appName);
                                    Console.WriteLine("Version: " + appVersion);
                                    Console.WriteLine("Is this the application? Enter 'Y' to continue:");
                                    string choice = Console.ReadLine();
                                    //Searches for other applications installed that matches what the user is searching for
                                    if (choice.ToLower() != "y")
                                    {
                                        Console.WriteLine("Aborted. Searching other apps.....");
                                        continue;
                                    }
                                    else
                                    {
                                        isFound = true;
                                    }
                                }

                                //If user has confirmed the app he/she is searching for, adds it to the list of apps to generate CVE reports for
                                if (isFound == true)
                                {
                                    // appVersion = "0.1.38.1"; //For testing, very old version of chrome, remove later
                                    //appVersion = "1511"; //For testing, very old version of windows 10, remove later
                                    // appVersion = "15.006.30060"; //Old version of acrobat reader DC
                                    // appVersion = "1.7.32"; //Old version of Burp Suite
                                    programsToCheck.Add(appName);
                                    programVersions.Add(appVersion);
                                    break;
                                }
                            }
                            // If a match was not confirmed by the user for any of the applications installed
                            if (isFound == false)
                            {
                                Console.WriteLine("\nApplication not found. Please try again.\n");
                            }

                            isFound = false;
                        }

                        if (isSearching == true)
                        {
                            int counter = 0;
                            String dateTimeString = DateTime.Now.ToString("MMddyyyyHHmmss");
                            //Generates CVE reports for all applications the user has confirmed
                            foreach (string appname in programsToCheck)
                            {
                                CVEGenerator.generateTextReport(appname, programVersions[counter], dateTimeString);
                                counter++;

                            }
                        }
                    }
                }
            }
        }

        //Main method to generate the CVE Report
        public static void generateTextReport(string appName, string appVersion, string dateTimeString)
        {
            Console.WriteLine("Generating your report for " + appName + ". This might take a while......");


            String reportTextFilename = appName.Replace("/", "-") + " CVE Results"; //CVE txt file filename 
            int noOfCVEs = 0;

            int currentYear = DateTime.Now.Year;

            //Loops through each CVE file to search for vulnerabilities for your application
            for (int y = 2002; y <= currentYear; y++)
            {
                //Code portion to parse the json file to a single C# object 
                JsonSerializer serializer = new JsonSerializer();
                CVEGenerator.RootObject rootObject = new CVEGenerator.RootObject();
                // If the CVE file for the particular year exists
                if (File.Exists(@Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + "\\nvdfiles\\nvdcve-1.0-" + y + ".json"))
                {
                    using (FileStream s = File.Open(@Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + "\\nvdfiles\\nvdcve-1.0-" + y + ".json", FileMode.Open)) //Opens the CVE file
                    using (StreamReader sr = new StreamReader(s))
                    using (JsonReader reader = new JsonTextReader(sr))
                    {
                        while (reader.Read())
                        {
                            // deserialize only when there's "{" character in the stream
                            if (reader.TokenType == JsonToken.StartObject)
                            {
                                //Deserializes the json file into a single C# root object to reference from
                                rootObject = serializer.Deserialize<CVEGenerator.RootObject>(reader);
                            }
                        }
                    }

                    //Loops through all CVE Items for the application selected
                    for (int x = 0; x < rootObject.CVE_Items.Count; x++)
                    {

                        if (rootObject.CVE_Items[x].cve.affects.vendor.vendor_data.Count > 0) //If the CVE has vendor data
                        {

                            for (int j = 0; j < rootObject.CVE_Items[x].cve.affects.vendor.vendor_data[0].product.product_data.Count; j++)
                            {
                                //programNameinJSON is the combination of the vendor name and the actual product name together, (e.g 'google' +'chrome' = 'google chrome'. Compared with the program name the user wishes to check vulnerabilities with
                                string programNameinJSON = rootObject.CVE_Items[x].cve.affects.vendor.vendor_data[0].vendor_name + " " + rootObject.CVE_Items[x].cve.affects.vendor.vendor_data[0].product.product_data[j].product_name;
                                programNameinJSON = programNameinJSON.Replace("_", " ");

                                if (String.Compare(programNameinJSON, appName, StringComparison.OrdinalIgnoreCase) == 0 || String.Compare(appName, rootObject.CVE_Items[x].cve.affects.vendor.vendor_data[0].product.product_data[j].product_name.Replace("_", " "), StringComparison.OrdinalIgnoreCase) == 0 || appName.ToLower().Contains(rootObject.CVE_Items[x].cve.affects.vendor.vendor_data[0].product.product_data[j].product_name.Replace("_", " ").ToLower())) //If the application is affected by the CVE
                                {
                                    //Loops through all versions affected for a match of your current version
                                    for (int i = 0; i < rootObject.CVE_Items[x].cve.affects.vendor.vendor_data[0].product.product_data[j].version.version_data.Count; i++)
                                    {

                                        //If your version is affected, prompts user
                                        if (appVersion == rootObject.CVE_Items[x].cve.affects.vendor.vendor_data[0].product.product_data[j].version.version_data[i].version_value)
                                        {
                                            String path = @Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + "\\cvereports" + dateTimeString + "\\" + reportTextFilename + ".txt"; //path of the current CVE text file to be created

                                            try
                                            {
                                                System.IO.Directory.CreateDirectory(@Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + "\\cvereports" + dateTimeString); //Creates the cvereports folder in Documents
                                                //Writes to the CVE txt file
                                                using (FileStream fs = new FileStream(path, FileMode.Append, FileAccess.Write))
                                                {
                                                    Byte[] info;
                                                    byte[] newline = Encoding.ASCII.GetBytes(Environment.NewLine);
                                                    if (noOfCVEs == 0) // Writes only at the start of the file
                                                    {
                                                        info = new UTF8Encoding(true)
.GetBytes("\n#######################################");
                                                        fs.Write(info, 0, info.Length);


                                                        fs.Write(newline, 0, newline.Length);

                                                        info = new UTF8Encoding(true)
                                                            .GetBytes(appName + " version " + appVersion + " CVE results:");
                                                        fs.Write(info, 0, info.Length);
                                                        fs.Write(newline, 0, newline.Length);

                                                        info = new UTF8Encoding(true)
                                                .GetBytes("#######################################");
                                                        fs.Write(info, 0, info.Length);
                                                        fs.Write(newline, 0, newline.Length);

                                                    }
                                                    noOfCVEs++;
                                                    fs.Write(newline, 0, newline.Length);
                                                    info = new UTF8Encoding(true)
.GetBytes("CVE ID: " + rootObject.CVE_Items[x].cve.CVE_data_meta.ID);
                                                    fs.Write(info, 0, info.Length);
                                                    fs.Write(newline, 0, newline.Length);
                                                    Console.WriteLine("CVE ID: " + rootObject.CVE_Items[x].cve.CVE_data_meta.ID + " detected.");

                                                    info = new UTF8Encoding(true)
.GetBytes("Description:" + rootObject.CVE_Items[x].cve.description.description_data[0].value);
                                                    fs.Write(info, 0, info.Length);
                                                    fs.Write(newline, 0, newline.Length);
                                                    try
                                                    {
                                                        info = new UTF8Encoding(true)
.GetBytes("Attack Vector: " + rootObject.CVE_Items[x].impact.baseMetricV3.cvssV3.attackVector);
                                                        fs.Write(info, 0, info.Length);
                                                        fs.Write(newline, 0, newline.Length);
                                                    }
                                                    catch (Exception e)
                                                    {

                                                    }

                                                    try
                                                    {
                                                        info = new UTF8Encoding(true)
.GetBytes("Attack Complexity: " + rootObject.CVE_Items[x].impact.baseMetricV3.cvssV3.attackComplexity);
                                                        fs.Write(info, 0, info.Length);
                                                        fs.Write(newline, 0, newline.Length);
                                                    }
                                                    catch (Exception e)
                                                    {
                                                    }

                                                    try
                                                    {
                                                        info = new UTF8Encoding(true)
.GetBytes("Privileges Required: " + rootObject.CVE_Items[x].impact.baseMetricV3.cvssV3.privilegesRequired);
                                                        fs.Write(info, 0, info.Length);
                                                        fs.Write(newline, 0, newline.Length);
                                                    }
                                                    catch (Exception e)
                                                    {
                                                    }

                                                    try
                                                    {
                                                        info = new UTF8Encoding(true)
.GetBytes("User Interaction: " + rootObject.CVE_Items[x].impact.baseMetricV3.cvssV3.userInteraction);
                                                        fs.Write(info, 0, info.Length);
                                                        fs.Write(newline, 0, newline.Length);
                                                    }
                                                    catch (Exception e)
                                                    {

                                                    }

                                                    try
                                                    {
                                                        info = new UTF8Encoding(true)
.GetBytes("Confidentiality Impact: " + rootObject.CVE_Items[x].impact.baseMetricV3.cvssV3.confidentialityImpact);
                                                        fs.Write(info, 0, info.Length);
                                                        fs.Write(newline, 0, newline.Length);
                                                    }

                                                    catch (Exception e)
                                                    {
                                                    }

                                                    try
                                                    {
                                                        info = new UTF8Encoding(true)
.GetBytes("Integrity Impact: " + rootObject.CVE_Items[x].impact.baseMetricV3.cvssV3.integrityImpact);
                                                        fs.Write(info, 0, info.Length);
                                                        fs.Write(newline, 0, newline.Length);
                                                    }
                                                    catch (Exception e)
                                                    {

                                                    }

                                                    try
                                                    {
                                                        info = new UTF8Encoding(true)
.GetBytes("Availability Impact: " + rootObject.CVE_Items[x].impact.baseMetricV3.cvssV3.attackComplexity);
                                                        fs.Write(info, 0, info.Length);
                                                        fs.Write(newline, 0, newline.Length);

                                                    }
                                                    catch (Exception e)
                                                    {
                                                    }

                                                    try
                                                    {
                                                        info = new UTF8Encoding(true)
.GetBytes("Base Score: " + rootObject.CVE_Items[x].impact.baseMetricV3.cvssV3.baseScore);
                                                        fs.Write(info, 0, info.Length);
                                                        fs.Write(newline, 0, newline.Length);
                                                    }
                                                    catch (Exception e)
                                                    {
                                                    }
                                                    try
                                                    {
                                                        info = new UTF8Encoding(true)
.GetBytes("Base Severity: " + rootObject.CVE_Items[x].impact.baseMetricV3.cvssV3.baseSeverity + "\n");
                                                        fs.Write(info, 0, info.Length);
                                                        fs.Write(newline, 0, newline.Length);


                                                    }
                                                    catch (Exception e)
                                                    {

                                                    }

                                                }

                                            }
                                            catch (Exception e)
                                            {
                                                Console.WriteLine("Error occurred when trying to create report file");
                                                Console.WriteLine(e.Message);
                                                return;
                                            }

                                        }
                                        else
                                        {

                                        }
                                    }

                                }
                            }
                        }
                    }

                }
                else
                {
                    Console.WriteLine("\n##########################################################");
                    Console.WriteLine(y + " CVE json file for the year " + y + " does not exist at Documents//nvdfiles.");
                    Console.WriteLine("##########################################################\n");
                }
            }

            if (noOfCVEs > 0)
            {
                Console.WriteLine("\n###################################################################################");
                Console.WriteLine("CVE report saved to Documents\\cvereports" + dateTimeString + " folder as: " + reportTextFilename + ".txt. There are a total of " + noOfCVEs + " found.");
                Console.WriteLine("###################################################################################\n");
            }
            else
            {
                Console.WriteLine("\n###################################################################################");
                Console.WriteLine("No CVEs detected for " + appName + ".");
                Console.WriteLine("###################################################################################\n");
            }
        }

        //Function to dl the CVE json files from NVD website
        public static void dlCVEDB()
        {
            Console.WriteLine("Downloading NVD Json Files onto Documents\\nvdfiles......");


            using (var client = new WebClient())
            {
                client.Headers.Add("user-agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; .NET CLR 1.0.3705;)");
                int currentYear = DateTime.Now.Year;
                for (int i = currentYear; i > 2001; i--)
                {
                    try
                    {
                        //If the json file does not already exists in Documents\nvdfiles, download it
                        if (File.Exists(@Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + "\\nvdfiles\\nvdcve-1.0-" + i + ".json") == false)
                        {
                            client.DownloadFile("https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-" + i + ".json.zip", @Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + "\\nvd" + i + ".zip");
                            ZipFile.ExtractToDirectory(@Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + "\\nvd" + i + ".zip", @Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + "\\nvdfiles");
                            Console.WriteLine("CVE json file for year " + i + " has been downloaded.");
                        }
                        //else if already exists, no need tod download
                        else
                        {
                            Console.WriteLine("CVE JSON file for the year " + i + " already exists in Documents\\nvdfiles.");
                        }

                    }
                    catch (Exception e)
                    {


                    }
                }
            }

        }

        //Function to check your windows version, if it exists. Returns "" if doesn't exist
        public static string checkWindowsVersion()
        {
            string Version = (string)Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion", "ProductName", null);
            string releaseId = "";
            if (Version != null)
            {
                releaseId = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ReleaseId", "").ToString();
                Console.WriteLine("Windows 10 build number " + releaseId);
            }


            return releaseId;
        }

        //Function to check your windows OS type
        public static string checkWindowsOS()
        {
            string windowsOS = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName", "").ToString();
            if (windowsOS.ToLower().Contains("windows 10"))
            {
                return "Windows 10";
            }
            else if (windowsOS.ToLower().Contains("windows 8.1"))
            {
                return "Windows 8.1";
            }

            else if (windowsOS.ToLower().Contains("windows 7"))
            {
                return "Windows 7";
            }

            else if (windowsOS.ToLower().Contains("windows server 2019"))
            {
                return "Windows Server 2019";
            }

            else if (windowsOS.ToLower().Contains("windows server 2019"))
            {
                return "Windows Server 2019";
            }

            else if (windowsOS.ToLower().Contains("windows server 2016"))
            {
                return "Windows Server 2016";
            }

            else if (windowsOS.ToLower().Contains("windows server 2012 r2"))
            {
                return "Windows Server 2012 r2";
            }

            else if (windowsOS.ToLower().Contains("windows 8"))
            {
                return "Windows 8";
            }

            else if (windowsOS.ToLower().Contains("windows server 2012"))
            {
                return "Windows Server 2012";
            }

            else if (windowsOS.ToLower().Contains("windows server 2008 r2"))
            {
                return "Windows Server 2008 r2";
            }

            else if (windowsOS.ToLower().Contains("windows server 2008"))
            {
                return "Windows Server 2008";
            }

            else if (windowsOS.ToLower().Contains("windows vista"))
            {
                return "Windows Vista";
            }

            else if (windowsOS.ToLower().Contains("windows server 2003 r2"))
            {
                return "Windows Server 2003 r2";
            }

            else if (windowsOS.ToLower().Contains("windows server 2003"))
            {
                return "Windows Server 2003";
            }

            else if (windowsOS.ToLower().Contains("windows xp"))
            {
                return "Windows XP";
            }

            else if (windowsOS.ToLower().Contains("windows 2000"))
            {
                return "Windows 2000";
            }

            else if (windowsOS.ToLower().Contains("windows me"))
            {
                return "Windows ME";
            }

            else if (windowsOS.ToLower().Contains("windows 98"))
            {
                return "Windows 98";
            }

            else
            {
                return "";
            }
        }

        //Function to check for internet connection
        public static bool checkForInternetConnection()
        {
            try
            {
                using (var client = new WebClient())
                using (client.OpenRead("http://www.google.com"))
                {
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }
    }
}

