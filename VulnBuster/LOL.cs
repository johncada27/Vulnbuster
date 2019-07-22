using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.Serialization.Json;
using System.Text;
using YamlDotNet.RepresentationModel;

namespace VulnBuster
{
    public class LOL
    {
        //Class to store url objects
        public class LOLInfo
        {
            public string download_url { get; set; }
            //        public short Contributions { get; set; }
            public string name { get; set; }
            //
            public override string ToString()
            {
                return download_url;
            }
        }
        
         public static void getLOLinfo()
        {
            Console.WriteLine("Would you like to download the latest LOL data? Key in 'Y' to download. Note that the program will not work if you have not download these files at least once:");
            string option = Console.ReadLine();
            if (option.ToLower() == "y")
            {
                if (!CVEGenerator.checkForInternetConnection())
                {
                    Console.WriteLine("\n#######################################");
                    Console.WriteLine("You do not have internet access to download LOL info. Quit to try again.");
                    Console.WriteLine("#######################################\n");
                    Console.WriteLine("Skipping download........\nPress enter to continue");
                    Console.ReadLine();
                    viewLOLInfo();
                }
                else
                {
                    getURL(); //Downloads LOLBin info
                    viewLOLInfo(); // Main function to display found LOLBins and execute permissions 
                }

            }
            else
            {
                viewLOLInfo();
            }
        }

        private static void viewLOLInfo()
        {
            Console.Clear();
            Console.Write("Searching for LOLBins please wait...");
            var sw = new Stopwatch();
            sw.Start();
            string[] filePaths = Directory.GetFiles(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "LOLInfo\\"), "*.yml", SearchOption.TopDirectoryOnly); //specify path to yml directory
            SearchFile sf = new SearchFile();
            

            if (filePaths.Length > 0)
            {
                try
                {
                    foreach(var filePath in filePaths)
                    {
                        var lolFileName = readLOLInfo("Name", filePath); // Retrieves filename entry from all yml files
                        var searchResult = sf.GetFiles(lolFileName); // Searches & retrieves files matching filename from yml
                        sf.DisplayResults(searchResult, lolFileName); // Displays result of previous search


                    }
                    sw.Stop();
                    Console.WriteLine("Total LOLBin search took {0} secs\n", sw.Elapsed.TotalSeconds); // Display total time taken for LOLBin search
                }
                catch (Exception ex)
                {
                    Console.WriteLine("LOLBin search failed. Please re-run the tool again.");
                }
            }
        }

        //Retrieves yml files from repo and downloads them
        private static void getURL()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            const string Url = "https://api.github.com/repos/LOLBAS-Project/LOLBAS/contents/yml/OSBinaries";
            var client = new WebClient();
            client.Headers.Add("User-Agent", "Nothing");

            client.DownloadStringCompleted += (sender, e) =>
            {
                var serializer = new DataContractJsonSerializer(typeof(List<LOLInfo>));

                using (var ms = new MemoryStream(Encoding.Unicode.GetBytes(e.Result)))
                {
                    var urlList = (List<LOLInfo>)serializer.ReadObject(ms);
                    Console.WriteLine("Downloading Files please wait...");
                    foreach (var url in urlList)
                    {

                        dlURL(url.download_url, url.name, urlList.Count);
                    }
                    Console.Clear();
                    Console.Write("All downloads done. Press enter to continue...");
                }
            };
            
            client.DownloadStringAsync(new Uri(Url));
            Console.ReadLine();

        }
        
        //Downloads specified url
        private static void dlURL(string urlString, string name, int count)
        {
            var uri = new Uri(urlString);
            var client = new WebClient();
            client.Headers.Add("User-Agent", "Nothing");
            var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "LOLInfo\\");
            Directory.CreateDirectory(path);
            client.DownloadFile(uri, @path + name);



        }
        
        //Reads specified node from yml file and returns value
        private static string readLOLInfo(string parent, string ymlFile)
        {
            var resultList = new List<string>();
            // Setup the input
            using (var input = new StreamReader(ymlFile))
            {

                //Load the stream
                var yaml = new YamlStream();
                yaml.Load(input);

                // Examine the stream
                var mapping =
                    (YamlMappingNode)yaml.Documents[0].RootNode;
                return mapping.Children[new YamlScalarNode(parent)].ToString();

                
            }
        }
    }
}