using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace VulnBuster
{
    
    //Returns list of fileinfo objects matching filename
    public class SearchFile
    {
        public List<FileInfo> GetFiles(string filename)
        {
            var di = new DirectoryInfo(@"C:\");
            var directories = di.GetDirectories();
            var files = new List<FileInfo>();

            Parallel.ForEach(directories, directoryInfo =>
            {
                try
                {
                    GetFilesFromDirectory(directoryInfo.FullName, files, filename);
                }
                catch (UnauthorizedAccessException)
                {
                }
            });
            return files;
        }

        //Recursive searches for  file matching filename
        private void GetFilesFromDirectory(string directory, List<FileInfo> files, string filename)
        {
            //Recursive function to retrieve all files matching specific LOLBin
            var di = new DirectoryInfo(directory);
            var fs = di.GetFiles(filename, SearchOption.TopDirectoryOnly).Where(s=>s.Extension.Equals(".exe"));
            files.AddRange(fs);
            var directories = di.GetDirectories();


            Parallel.ForEach(directories, directoryInfo =>
            {
                try
                {
                    GetFilesFromDirectory(directoryInfo.FullName, files, filename);
                }
                catch (UnauthorizedAccessException)
                {
                }
            });
        }
        
        //Used to hide GUI error messages
        [DllImport("kernel32.dll")]
        static extern ErrorModes     SetErrorMode( ErrorModes uMode );
        [Flags]
        public enum        ErrorModes : uint
        {
            SYSTEM_DEFAULT         = 0x0,
            SEM_FAILCRITICALERRORS     = 0x0001,
            SEM_NOALIGNMENTFAULTEXCEPT = 0x0004,
            SEM_NOGPFAULTERRORBOX      = 0x0002,
            SEM_NOOPENFILEERRORBOX     = 0x8000
        }

        //Displays search and execute permission for LOLBin
        public void DisplayResults(List<FileInfo> files, string filename)
        {
            //Displays found LOLBins as well as execute permissions
            if (files.Count > 0 && files!=null)
            {
                Console.Write("\n\nFound {0} in the following paths(* denotes user has no execute permission):\n------------------------------\n", filename);
                
                Parallel.ForEach(files, file =>
                {
                    
                        var hasPerm = CheckPerm(file.DirectoryName, filename);
                        if (!hasPerm)
                            Console.WriteLine("* " + file.DirectoryName);
                        else
                            Console.WriteLine(file.DirectoryName);
                    
                    

                });
            }




        }
        
        //function to check if user has execute rights for file
        private static bool CheckPerm(string path,string filename)
        {
            var hasPerm = true;
            Process proc = new Process();
            try
            {

                var fullPath=Path.Combine(path, filename);
                proc.StartInfo = new ProcessStartInfo(fullPath);
                proc.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                proc.StartInfo.UseShellExecute = false;
                proc.StartInfo.RedirectStandardError = true;
                proc.StartInfo.RedirectStandardInput = true;
                var oldMode = SetErrorMode(ErrorModes.SEM_FAILCRITICALERRORS);
                proc.Start();
                SetErrorMode(oldMode );
                proc.Kill();

            }

            catch (Exception ex)
            {
                if(ex.Message.Equals("Access is denied") || ex.Message.Equals("The requested operation requires elevation"))
                    hasPerm = false;
            }
      
            return hasPerm;

        }


    }
    
}