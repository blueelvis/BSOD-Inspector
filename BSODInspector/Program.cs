using System;
using System.Diagnostics;
using System.IO;
using Microsoft.VisualBasic.Devices;
using Microsoft.Win32;
using System.Management;
using System.IO.Compression;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Runtime.InteropServices;

namespace BSODInspector
{
    internal class Program
    {
        //##    Methods for Flashing the Taskbar window of the inactive process
        [DllImport("user32.dll")]
        private static extern bool FlashWindow(IntPtr hwnd, bool bInvert);
        //##    END

        private static void Main()
        {
            Console.WriteLine("####################################");
            Console.WriteLine("BSOD Inspector");
            Console.WriteLine("####################################");
            Console.WriteLine(Environment.NewLine + "Created By - blueelvis");
            Console.WriteLine("Special Thanks - John D. Carrona (Microsoft MVP)" + Environment.NewLine +
                              Environment.NewLine);
            string zipFileName = Environment.MachineName + "_" + DateTime.Now.ToString("G") + ".zip";
            zipFileName =
                zipFileName.Replace(" ", "_")
                    .Replace("\\", "_")
                    .Replace(":", "_")
                    .Replace("-", "_")
                    .Replace("/", "_");
            string tempDirectory = Path.GetTempPath() + @"blueelvis";
            string systemDrive = Path.GetPathRoot(Environment.SystemDirectory);
            string applicationVersion = "1.0.3";

            ComputerInfo sysinfo = new ComputerInfo();


            if (Directory.Exists(tempDirectory))
            {
                DirectoryInfo dInfo = new DirectoryInfo(tempDirectory);
                DirectorySecurity dSecurity = dInfo.GetAccessControl();
                dSecurity.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.FullControl,
                    InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit,
                    PropagationFlags.NoPropagateInherit, AccessControlType.Allow));
                dInfo.SetAccessControl(dSecurity);
                foreach (var existingFiles in Directory.GetFiles(tempDirectory))
                    File.Delete(existingFiles);
                Console.WriteLine(DateTime.Now.ToString("G") + "\t - Deleted Existing Temporary Files\n\n");
            }
            else
            {
                Directory.CreateDirectory(tempDirectory);
                DirectoryInfo dInfo = new DirectoryInfo(tempDirectory);
                DirectorySecurity dSecurity = dInfo.GetAccessControl();
                dSecurity.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.FullControl,
                    InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit,
                    PropagationFlags.NoPropagateInherit, AccessControlType.Allow));
                dInfo.SetAccessControl(dSecurity);
                
            }




            // =======================================================================================

            Thread msinfoThread = new Thread(MsinfoReportThread);
            msinfoThread.Start();
            Console.WriteLine(DateTime.Now.ToString("G") + "\t - Started Collecting the MSINFO32 Report \n\n");


            // =======================================================================================

            Console.WriteLine(DateTime.Now.ToString("G") + "\t - Copying Dump files if any\n\n");
            if (Directory.Exists(systemDrive + @"Windows\Minidump\"))
                foreach (var file in Directory.GetFiles(systemDrive + @"Windows\Minidump\"))
                {
                    if (file != null)
                        File.Copy(file, Path.Combine(tempDirectory, Path.GetFileName(file)), true);
                }

            // ======================================================================================


            // ======================================================================================
            Console.WriteLine(DateTime.Now.ToString("G") + "\t - Querying System for Drivers\n\n");
            using (StreamWriter fileWriter = new StreamWriter(tempDirectory + @"\drivertable.txt"))
            {
                using (Process driverTableQuery = new Process())
                {
                    if (File.Exists(Environment.SystemDirectory + @"\driverquery.exe"))
                    {
                        driverTableQuery.StartInfo.FileName = Environment.SystemDirectory + @"\driverquery.exe";
                        driverTableQuery.StartInfo.Arguments = @"/FO table /v";
                        driverTableQuery.StartInfo.RedirectStandardOutput = true;
                        driverTableQuery.StartInfo.UseShellExecute = false;
                        driverTableQuery.Start();
                        fileWriter.WriteLine(driverTableQuery.StandardOutput.ReadToEnd());
                        driverTableQuery.WaitForExit();
                        fileWriter.Close();
                        driverTableQuery.Close();

                    }
                    else
                    {
                        Console.WriteLine("Driverquery.exe not found in system");
                    }

                }
            }


            // ======================================================================================

            using (StreamWriter fileWriter = new StreamWriter(tempDirectory + @"\driverlist.txt"))
            {
                using (Process driverListQuery = new Process())
                {
                    if (File.Exists(Environment.SystemDirectory + @"\driverquery.exe"))
                    {
                        driverListQuery.StartInfo.FileName = Environment.SystemDirectory + @"\driverquery.exe";
                        driverListQuery.StartInfo.Arguments = @"/FO list";
                        driverListQuery.StartInfo.RedirectStandardOutput = true;
                        driverListQuery.StartInfo.UseShellExecute = false;
                        driverListQuery.Start();
                        fileWriter.WriteLine(driverListQuery.StandardOutput.ReadToEnd());
                        driverListQuery.WaitForExit();
                        fileWriter.Close();
                        driverListQuery.Close();
                    }
                    else
                    {
                        Console.WriteLine("DriverQuery.exe not found in system");
                    }
                }

            }

            // ==================================================================================
            Console.WriteLine(DateTime.Now.ToString("G") + Environment.NewLine + "\t - Generating the DXDIAG Report" +
                              Environment.NewLine);
            using (Process driverListQuery = new Process())
            {
                if (File.Exists(Environment.SystemDirectory + @"\dxdiag.exe"))
                {
                    driverListQuery.StartInfo.FileName = Environment.SystemDirectory + @"\dxdiag.exe";
                    driverListQuery.StartInfo.Arguments = @"/t " + "\"" + tempDirectory + @"\dxdiag.txt" + "\"";
                    driverListQuery.Start();
                    driverListQuery.WaitForExit();
                    driverListQuery.Close();
                }
                else
                {
                    Console.WriteLine("DxDiag.exe not found in system");
                }
            }

            // =================================================================================
            Console.WriteLine(DateTime.Now.ToString("G") + "\t - Generating System Event Log\n\n");
            using (Process eventviewerProcess = new Process())
            {
                if (File.Exists(Environment.SystemDirectory + @"\wevtutil.exe"))
                {
                    eventviewerProcess.StartInfo.FileName = Environment.SystemDirectory + @"\wevtutil.exe";
                    eventviewerProcess.StartInfo.Arguments = "epl " + "System " + "\"" + tempDirectory +
                                                             @"\SystemEventLog.evtx" + "\"";
                    eventviewerProcess.Start();
                    eventviewerProcess.WaitForExit();
                    eventviewerProcess.Close();
                }
                else
                {
                    Console.WriteLine("Wevtutil.exe not found in system");
                }
            }

            // ==================================================================================

            // =================================================================================
            Console.WriteLine(DateTime.Now.ToString("G") + "\t - Generating Application Event Log\n\n");
            using (Process eventviewerProcess = new Process())
            {
                if (File.Exists(Environment.SystemDirectory + @"\wevtutil.exe"))
                {
                    eventviewerProcess.StartInfo.FileName = Environment.SystemDirectory + @"\wevtutil.exe";
                    eventviewerProcess.StartInfo.Arguments = "epl " + "Application " + "\"" + tempDirectory +
                                                             @"\ApplicationEventLog.evtx" + "\"";
                    eventviewerProcess.Start();
                    eventviewerProcess.WaitForExit();
                    eventviewerProcess.Close();
                }
                else
                {
                    Console.WriteLine("Wevtutil.exe not found in system");
                }
            }

            // ==================================================================================
            if (File.Exists(Environment.SystemDirectory + @"\drivers\etc\hosts"))
                File.Copy(Environment.SystemDirectory + @"\drivers\etc\hosts", tempDirectory + @"\hosts.txt", true);
            Console.WriteLine(DateTime.Now.ToString("G") + "\t - Processing the HOSTS file\n\n");
            // ==================================================================================
            Console.Write(DateTime.Now.ToString("G") +
                          "\t - Generating detailed list of installed Windows Updates\n\n");
            using (StreamWriter fileWriter = new StreamWriter(tempDirectory + @"\InstalledWindowsUpdates.txt"))
            {
                using (Process wmicHotfixList = new Process())
                {
                    if (File.Exists(Environment.SystemDirectory + @"\wbem\wmic.exe"))
                    {
                        wmicHotfixList.StartInfo.FileName = Environment.SystemDirectory + @"\wbem\wmic.exe";
                        wmicHotfixList.StartInfo.Arguments = @"qfe list /format:table";
                        wmicHotfixList.StartInfo.RedirectStandardOutput = true;
                        wmicHotfixList.StartInfo.UseShellExecute = false;
                        wmicHotfixList.Start();
                        fileWriter.WriteLine(wmicHotfixList.StandardOutput.ReadToEnd());
                        wmicHotfixList.WaitForExit();
                        fileWriter.Close();
                        wmicHotfixList.Close();
                    }
                    else
                    {
                        Console.WriteLine("WMIC.exe not found in system");
                    }
                }

            }

            // ====================================================================================
            Console.WriteLine(DateTime.Now.ToString("G") + "\t - Generating SystemInfo\n\n");
            using (StreamWriter fileWriter = new StreamWriter(tempDirectory + @"\systeminfo.txt"))
            {
                using (Process systeminfo = new Process())
                {
                    if (File.Exists(Environment.SystemDirectory + @"\systeminfo.exe"))
                    {
                        systeminfo.StartInfo.FileName = Environment.SystemDirectory + @"\systeminfo.exe";
                        systeminfo.StartInfo.RedirectStandardOutput = true;
                        systeminfo.StartInfo.UseShellExecute = false;
                        systeminfo.Start();
                        fileWriter.WriteLine(systeminfo.StandardOutput.ReadToEnd());
                        systeminfo.WaitForExit();
                        fileWriter.Close();
                        systeminfo.Close();
                    }
                    else
                    {
                        Console.WriteLine("Systeminfo.exe not found in system");
                    }
                }

            }

            // ==================================================================================
            if (Environment.Is64BitOperatingSystem)
            {
                Console.WriteLine(DateTime.Now.ToString("G") + "\t - Exporting x86 Uninstall Registry\n\n");

                using (Process uninstallListx86 = new Process())
                {
                    if (File.Exists(Environment.SystemDirectory + @"\reg.exe"))
                    {
                        uninstallListx86.StartInfo.FileName = Environment.SystemDirectory + @"\reg.exe";
                        uninstallListx86.StartInfo.Arguments =
                            @"export HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\ " + "\"" +
                            tempDirectory +
                            @"\uninstallx86.txt" + "\"";
                        uninstallListx86.Start();
                        uninstallListx86.WaitForExit();
                        uninstallListx86.Close();
                    }
                    else
                    {
                        Console.WriteLine("reg.exe not found in system");
                    }
                }
            }

            // =================================================================================


            // ================================================================================
            Console.WriteLine(DateTime.Now.ToString("G") + "\t - Generating Tasklist\n\n");
            using (StreamWriter fileWriter = new StreamWriter(tempDirectory + @"\tasklist.txt"))
            {
                using (Process taskList = new Process())
                {
                    if (File.Exists(Environment.SystemDirectory + @"\tasklist.exe"))
                    {
                        taskList.StartInfo.FileName = Environment.SystemDirectory + @"\tasklist.exe";
                        taskList.StartInfo.Arguments = "/fo:table";
                        taskList.StartInfo.RedirectStandardOutput = true;
                        taskList.StartInfo.UseShellExecute = false;
                        taskList.Start();
                        fileWriter.WriteLine(taskList.StandardOutput.ReadToEnd());
                        taskList.WaitForExit();
                        fileWriter.Close();
                        taskList.Close();
                    }
                    else
                    {
                        Console.WriteLine("Tasklist.exe not found in system");
                    }
                }

            }

            // ================================================================================
            Console.WriteLine(DateTime.Now.ToString("G") + "\t - Generating List of Currently Active Services\n\n");
            using (StreamWriter fileWriter = new StreamWriter(tempDirectory + @"\activeservices.txt"))
            {
                using (Process activeServices = new Process())
                {
                    if (File.Exists(Environment.SystemDirectory + @"\net.exe"))
                    {
                        activeServices.StartInfo.FileName = Environment.SystemDirectory + @"\net.exe";
                        activeServices.StartInfo.Arguments = "start";
                        activeServices.StartInfo.RedirectStandardOutput = true;
                        activeServices.StartInfo.UseShellExecute = false;
                        activeServices.Start();
                        fileWriter.WriteLine(activeServices.StandardOutput.ReadToEnd());
                        activeServices.WaitForExit();
                        fileWriter.Close();
                        activeServices.Close();
                    }
                    else
                    {
                        Console.WriteLine("Net.exe not found in system");
                    }
                }

            }

            // ================================================================================
            Console.WriteLine(DateTime.Now.ToString("G") + "\t - Generating List of All Services\n\n");
            using (StreamWriter fileWriter = new StreamWriter(tempDirectory + @"\all_services_status.txt"))
            {
                using (Process allServicesList = new Process())
                {
                    if (File.Exists(Environment.SystemDirectory + @"\sc.exe"))
                    {
                        allServicesList.StartInfo.FileName = Environment.SystemDirectory + @"\sc.exe";
                        allServicesList.StartInfo.Arguments = "query";
                        allServicesList.StartInfo.RedirectStandardOutput = true;
                        allServicesList.StartInfo.UseShellExecute = false;
                        allServicesList.Start();
                        fileWriter.WriteLine(allServicesList.StandardOutput.ReadToEnd());
                        allServicesList.WaitForExit();
                        fileWriter.Close();
                        allServicesList.Close();
                    }
                    else
                    {
                        Console.WriteLine("sc.exe not found in system");
                    }
                }

            }

            // =================================================================================
            {
                Console.WriteLine(DateTime.Now.ToString("G") + "\t - Exporting Uninstall Registry\n\n");

                using (Process uninstallListx64 = new Process())
                {
                    if (File.Exists(systemDrive + @"\Windows\System32\reg.exe"))
                    {
                        if (!Environment.Is64BitOperatingSystem)
                        {
                            uninstallListx64.StartInfo.FileName = systemDrive + @"\Windows\System32\reg.exe";
                            uninstallListx64.StartInfo.Arguments =
                                @"export HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall " +
                                "\"" + tempDirectory +
                                @"\uninstallx64.txt" + "\"" + "/reg:32";
                        }
                        else
                        {
                            uninstallListx64.StartInfo.FileName = systemDrive + @"\Windows\Sysnative\reg.exe";
                            uninstallListx64.StartInfo.Arguments =
                                @"export HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall " +
                                "\"" + tempDirectory + "\"" +
                                @"\uninstallx64.txt " + "\"" + "/reg:64";
                        }
                        uninstallListx64.StartInfo.UseShellExecute = false;
                        uninstallListx64.StartInfo.RedirectStandardOutput = true;
                        uninstallListx64.Start();
                        uninstallListx64.WaitForExit();
                        uninstallListx64.Close();
                    }
                    else
                    {
                        Console.WriteLine("reg.exe not found in system");
                    }
                }

            }

            // =================================================================================
            Console.WriteLine(DateTime.Now.ToString("G") + "\t - Collecting Miscellaneous Data\n\n");
            RegistryKey werSvcKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\WerSVC");
            string werStatus = (werSvcKey != null)
                ? Convert.ToString(werSvcKey.GetValue("Start"))
                : "werSVCKey Not Found";

            // ================================================================================

            RegistryKey kmsService =
                Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Service KMSELDI");
            var kmsStatus = (kmsService == null) ? 0 : 1;

            // ================================================================================

            string bootUpState = "", pagefilemanagement = "";
            using (Process wmic = new Process())
            {
                if (File.Exists(Environment.SystemDirectory + @"\wbem\wmic.exe"))
                {
                    wmic.StartInfo.FileName = Environment.SystemDirectory + @"\wbem\wmic.exe";

                    wmic.StartInfo.Arguments = "COMPUTERSYSTEM get BOOTUPSTATE /value";
                    wmic.StartInfo.UseShellExecute = false;
                    wmic.StartInfo.RedirectStandardOutput = true;
                    wmic.Start();
                    string output = wmic.StandardOutput.ReadToEnd();
                    wmic.WaitForExit();
                    wmic.Close();
                    output = output.Replace("\n", "");
                    bootUpState = output.Contains("BootupState") ? output.Replace("BootupState=", "") : "Cannot Query BootupState";
                    wmic.StartInfo.Arguments = "computersystem get AutomaticManagedPageFile /value";
                    wmic.Start();
                    pagefilemanagement = wmic.StandardOutput.ReadToEnd();
                    wmic.WaitForExit();
                    wmic.Close();
                    pagefilemanagement = pagefilemanagement.Replace("\n", "");
                    pagefilemanagement = pagefilemanagement.Replace("AutomaticManagedPageFile", "");
                }
                else
                    Console.WriteLine("WMIC.EXE Does not exist on the system");
            }

            // ===============================================================================

            if (!File.Exists(tempDirectory + @"\uninstallx86.txt"))
            {
                File.Create(tempDirectory + @"\uninstallx86.txt");
                Console.WriteLine(DateTime.Now.ToString("G") +
                              "\t - Blank File for x86 Uninstall List Created\n\n");
            }
            if (!File.Exists(tempDirectory + @"\uninstallx64.txt"))
            {
                File.Create(tempDirectory + @"\uninstallx64.txt");
                Console.WriteLine(DateTime.Now.ToString("G") +
                              "\t - Blank File for x64 Uninstall List Created\n\n");
            }
            using (var output = File.Create(tempDirectory + @"\uninstall-reg.txt"))
            {
                foreach (
                    var file in new[] { tempDirectory + @"\uninstallx86.txt", tempDirectory + @"\uninstallx64.txt" })
                {
                    using (var input = File.OpenRead(file))
                    {
                        input.CopyTo(output);
                    }
                }
            }

            using (
                StreamReader uninstallcombinedListReader = new StreamReader(tempDirectory + @"\uninstall-reg.txt"))
            {
                using (
                    StreamWriter filteredUninstallListWriter =
                        new StreamWriter(tempDirectory + @"\duplicatesimpleUninstall.txt"))
                {
                    while (uninstallcombinedListReader.Peek() >= 0)
                    {
                        string logFileContent = uninstallcombinedListReader.ReadLine();
                        string name = "", version = "", publisher = "";
                        if (logFileContent != null && logFileContent.Contains(@"[HKEY_LOCAL_MACHINE\"))
                        {
                            while (logFileContent != "")
                            {
                                logFileContent = uninstallcombinedListReader.ReadLine();
                                if (logFileContent != null && logFileContent.Contains("\"DisplayName\""))
                                {
                                    logFileContent = logFileContent.Replace("\"", "");
                                    logFileContent = logFileContent.Replace("DisplayName=", "");
                                    name = logFileContent + " (";
                                }
                                if (logFileContent != null && logFileContent.Contains("\"DisplayVersion\""))
                                {
                                    logFileContent = logFileContent.Replace("\"", "");
                                    logFileContent = logFileContent.Replace("DisplayVersion=", "");
                                    version = "Version : " + logFileContent + " - ";
                                }
                                if (logFileContent != null && logFileContent.Contains("\"Publisher\""))
                                {
                                    logFileContent = logFileContent.Replace("\"", "");
                                    logFileContent = logFileContent.Replace("Publisher=", "");
                                    publisher = logFileContent + " )";
                                }

                            }
                            if (name != "" && version != "" && publisher != "")
                                filteredUninstallListWriter.WriteLine(name + version + publisher);
                        }
                    }
                }

            }

            string infile = tempDirectory + @"\duplicatesimpleUninstall.txt";
            string outfile = tempDirectory + @"\simpleuninstall.txt";
            var contents = File.ReadAllLines(infile);
            Array.Sort(contents);
            File.WriteAllLines(outfile, contents);
            Console.WriteLine(DateTime.Now.ToString("G") +
                              "\t - Collecting List of Programs Installed On The System\n\n");
            using (TextReader reader = File.OpenText(outfile))
            {
                using (TextWriter writer = File.CreateText(tempDirectory + @"\uninstalllist.txt"))
                {
                    string currentLine;
                    string lastLine = null;

                    while ((currentLine = reader.ReadLine()) != null)
                    {
                        if (currentLine != lastLine)
                        {
                            writer.WriteLine(currentLine);
                            lastLine = currentLine;
                        }
                    }
                }
            }

            string osInstallDate = "",
                systemManufacturer = "",
                systemModel = "",
                biosVersion = "",
                pageFileLocation = "",
                pageFileSize = "";
            int hotfixInstalled = 0;


            using (Process wmic = new Process())
            {
                if (File.Exists(Environment.SystemDirectory + @"\wbem\wmic.exe"))
                {
                    wmic.StartInfo.FileName = Environment.SystemDirectory + @"\wbem\wmic.exe";

                    wmic.StartInfo.Arguments = "os get installdate /value";
                    wmic.StartInfo.UseShellExecute = false;
                    wmic.StartInfo.RedirectStandardOutput = true;
                    wmic.Start();
                    osInstallDate = wmic.StandardOutput.ReadToEnd();
                    wmic.WaitForExit();
                    wmic.Close();
                    osInstallDate = osInstallDate.Replace("\n", "").Replace("InstallDate=", "");
                    osInstallDate = ConvertDateTime(osInstallDate);

                    wmic.StartInfo.Arguments = "computersystem get manufacturer /value";
                    wmic.Start();
                    systemManufacturer = wmic.StandardOutput.ReadToEnd();
                    wmic.WaitForExit();
                    wmic.Close();
                    systemManufacturer = systemManufacturer.Replace("\n", "").Replace("Manufacturer=", "");

                    wmic.StartInfo.Arguments = "computersystem get model /value";
                    wmic.Start();
                    systemModel = wmic.StandardOutput.ReadToEnd();
                    wmic.WaitForExit();
                    wmic.Close();
                    systemModel = systemModel.Replace("\n", "").Replace("Model=", "");

                    wmic.StartInfo.Arguments = "bios get ReleaseDate /value";
                    wmic.Start();
                    biosVersion = wmic.StandardOutput.ReadToEnd();
                    wmic.WaitForExit();
                    wmic.Close();
                    biosVersion = biosVersion.Replace("\n", "").Replace("ReleaseDate=", "");
                    biosVersion = ConvertDateTime(biosVersion);

                    wmic.StartInfo.Arguments = "pagefile get Description /value";
                    wmic.Start();
                    pageFileLocation = wmic.StandardOutput.ReadToEnd();
                    wmic.WaitForExit();
                    wmic.Close();
                    pageFileLocation = pageFileLocation.Replace("\n", "").Replace("Description=", "");

                    wmic.StartInfo.Arguments = "pagefile get AllocatedBaseSize /value";
                    wmic.Start();
                    pageFileSize = wmic.StandardOutput.ReadToEnd();
                    wmic.WaitForExit();
                    wmic.Close();
                    pageFileSize = pageFileSize.Replace("\n", "").Replace("AllocatedBaseSize=", "");
                    pageFileSize += " MB";

                }
            }

            using (StreamReader systeminfoReader = new StreamReader(tempDirectory + @"\systeminfo.txt"))
            {
                using (StreamWriter goodsysinfoWriter = new StreamWriter(tempDirectory + @"\goodsysteminfo.txt"))
                {
                    int lineNumber = -1;
                    while (systeminfoReader.Peek() >= 0)
                    {
                        string logFileContent = systeminfoReader.ReadLine();
                        lineNumber++;
                        if (lineNumber == 7)
                            continue;
                        goodsysinfoWriter.WriteLine(logFileContent);

                    }
                }
            }

            using (StreamReader hotFixReader = new StreamReader(tempDirectory + @"\InstalledWindowsUpdates.txt"))
            {
                while (hotFixReader.Peek() >= 0)
                {
                    string logFileContent = hotFixReader.ReadLine();
                    if(logFileContent != null && logFileContent.Contains(@"http://"))
                        hotfixInstalled++;

                }
            }
            /////////////////////////////////////////////////////////////////////////////
            //          BSOD Inspector Log                                             //
            ////////////////////////////////////////////////////////////////////////////
            Console.WriteLine(DateTime.Now.ToString("G") + "\t - Generating Inspector Log File\n\n");
            using (StreamWriter bsodInspectorWriter = new StreamWriter(tempDirectory + @"\BSODInspector.txt"))
            {


                bsodInspectorWriter.Write(
                    "========================================================" + Environment.NewLine +
                    "############" + Environment.NewLine + "BSOD Inspector by blueelvis" + Environment.NewLine +
                    "Special Thanks - John D. Carrona (Microsoft MVP)" + Environment.NewLine);
                bsodInspectorWriter.WriteLine("Version :          " + applicationVersion);
                bsodInspectorWriter.WriteLine("OS :               " + sysinfo.OSFullName);
                bsodInspectorWriter.WriteLine("Boot Mode :        " + bootUpState);
                bsodInspectorWriter.WriteLine("OS Install Date :  " + osInstallDate);
                bsodInspectorWriter.Write(Environment.NewLine +
                                            "========================================================" +
                                            Environment.NewLine + Environment.NewLine);
                bsodInspectorWriter.Write("### SYSTEM INFO  ###" + Environment.NewLine);

                string antiviruswmipath = @"\\" + Environment.MachineName + @"\root\SecurityCenter2";
                string antivirusList = String.Empty;

                ObjectQuery antivirusObjectQuery = new ObjectQuery("SELECT displayName from AntivirusProduct");
                ManagementObjectSearcher avSearcher = new ManagementObjectSearcher(antiviruswmipath,
                    antivirusObjectQuery.QueryString);
                ManagementObjectCollection avcollection = avSearcher.Get();
                foreach (var o in avcollection)
                {
                    if (o != null)
                    {
                        var av = (ManagementObject)o;
                        if (av["displayName"].ToString()!="Antivirus")
                        {
                            antivirusList = antivirusList + av["displayName"] + ",";
                        }
                        
                    }
                }

                if (antivirusList == "" || antivirusList.Length <= 0)
                    antivirusList = "No Antivirus Found";
                else
                    antivirusList.Remove(antivirusList.Length - 1);
                bsodInspectorWriter.WriteLine("Antivirus = " + antivirusList);
                bsodInspectorWriter.WriteLine(kmsStatus == 0 ? "Activation = KMS NOT FOUND" : "Activation = Not Genuine");

                bsodInspectorWriter.WriteLine("Windows Updates = " + hotfixInstalled.ToString() + " Updates Installed");
                bsodInspectorWriter.WriteLine("Manufacturer = " + systemManufacturer);
                bsodInspectorWriter.WriteLine("Model = " + systemModel);
                bsodInspectorWriter.WriteLine("BIOS = " + biosVersion);
                bsodInspectorWriter.Write(Environment.NewLine + Environment.NewLine +
                                            "###  Dump Generation Settings  ###" + Environment.NewLine);
                bsodInspectorWriter.WriteLine(File.Exists(systemDrive + @"\pagefile.sys")
                    ? "Pagefile Location = Found on OS drive!"
                    : "Pagefile Location = Pagefile Not Found on OS Drive!");

                bsodInspectorWriter.WriteLine("Pagefile Size = " + pageFileSize);

                bsodInspectorWriter.WriteLine(pagefilemanagement.Contains("TRUE")
                    ? "Pagefile Managed by System = TRUE"
                    : "Pagefile Managed by System = FALSE");

                bsodInspectorWriter.WriteLine(werStatus == "3"
                    ? "WER Service Status = Set to Manual"
                    : "WER Service Status = Not Manual!");
                bsodInspectorWriter.Write(Environment.NewLine + Environment.NewLine + "###  DUMP FILE LIST ###" +
                                            Environment.NewLine + Environment.NewLine);

                if (Directory.Exists(systemDrive + @"Windows\Minidump"))
                    foreach (var file in Directory.GetFiles(systemDrive + @"Windows\Minidump"))
                    {
                        if (file != null)
                        {
                            bsodInspectorWriter.Write(Environment.NewLine);
                            bsodInspectorWriter.Write(file + "\t\t");
                            bsodInspectorWriter.Write(File.GetCreationTimeUtc(file));

                        }
                    }
                bsodInspectorWriter.WriteLine(Environment.NewLine);
                if (File.Exists(systemDrive + @"Windows\Memory.DMP"))
                {
                    FileInfo memoryDump = new FileInfo(systemDrive + @"Windows\Memory.DMP");
                    bsodInspectorWriter.WriteLine("->MEMORY.DMP Found");
                    bsodInspectorWriter.WriteLine("Size = " + memoryDump.Length / (1024 * 1024) + " MB");
                    bsodInspectorWriter.WriteLine("Date Of Creation = " +
                                                  "\t\t" + File.GetCreationTimeUtc(systemDrive + @"Windows\Memory.DMP"));
                }
                else
                {
                    bsodInspectorWriter.WriteLine("MEMORY.DMP not found");
                }

                string systemRestorewmipath = @"\\" + Environment.MachineName + @"\root\default";

                ObjectQuery sysRestoreObjectQuery = new ObjectQuery("SELECT * from SystemRestore");

                ManagementObjectSearcher srSearcher = new ManagementObjectSearcher(systemRestorewmipath,
                    sysRestoreObjectQuery.QueryString);

                ManagementObjectCollection srcollection = srSearcher.Get();

                bsodInspectorWriter.Write(Environment.NewLine + Environment.NewLine +
                                            "###  RECOVERY POINTS PRESENT  ###" + Environment.NewLine +
                                            "Description \t\t\t\t Date Of Creation" + Environment.NewLine);
                foreach (var o in srcollection)
                {
                    var sr = (ManagementObject)o;
                    if (sr == null) continue;

                    if (sr["Description"].ToString().Contains("Windows Update"))
                        bsodInspectorWriter.Write(sr["Description"] + "\t\t\t\t");
                    else
                        bsodInspectorWriter.Write(sr["Description"] + "\t\t\t");
                    var creationTime = sr["CreationTime"].ToString();
                    creationTime = ConvertDateTime(creationTime);
                    bsodInspectorWriter.Write(creationTime + Environment.NewLine);
                }
                if (srcollection.Count == 0)
                    bsodInspectorWriter.Write(Environment.NewLine + "No Recovery Points Found" +
                                                Environment.NewLine);
                bsodInspectorWriter.WriteLine(Environment.NewLine + Environment.NewLine + "###  MEMORY INFO  ###");
                bsodInspectorWriter.WriteLine("Total RAM = " + sysinfo.TotalPhysicalMemory / (1024 * 1024) + " MB");
                bsodInspectorWriter.WriteLine("Available RAM = " + sysinfo.AvailablePhysicalMemory / (1024 * 1024) +
                                                " MB");
                bsodInspectorWriter.WriteLine("PageFile Location = "+pageFileLocation);
                bsodInspectorWriter.WriteLine("Pagefile Size = " + pageFileSize);
                bsodInspectorWriter.Write(Environment.NewLine + Environment.NewLine +
                                            "~~~~~~~~~~~~~~~~~~~~~~~~~~~EOF~~~~~~~~~~~~~~~~~~~~~~~~~");
            }

            Console.WriteLine(DateTime.Now.ToString("G") + "\t - Removing Temporary Files\n\n");
            File.Delete(tempDirectory + @"\duplicatesimpleuninstall.txt");
            File.Delete(infile);
            File.Delete(outfile);
            File.Delete(tempDirectory + @"\uninstall-reg.txt");
            File.Delete(tempDirectory + @"\systeminfo.txt");
            File.Move(tempDirectory + @"\goodsysteminfo.txt", tempDirectory + @"\systeminfo.txt");
            File.Delete(tempDirectory + @"\goodsysteminfo.txt");
            using (StreamWriter greetings = new StreamWriter(tempDirectory + @"\greetings.txt"))
            {
                greetings.WriteLine("Greetings ^_^," + Environment.NewLine + Environment.NewLine +
                                    "The application has completed its job of collecting the diagnostics of your system." +
                                    Environment.NewLine +
                                    " Below are the details for the location of the ZIP file generated by this application -" +
                                    Environment.NewLine + Environment.NewLine + "Filename = " + zipFileName +
                                    Environment.NewLine + "Location = " +
                                    Environment.GetFolderPath(Environment.SpecialFolder.Desktop) +
                                    Environment.NewLine + Environment.NewLine);
                string quote = Quotes();
                if (quote != "0")
                {
                    greetings.WriteLine(Environment.NewLine + "Do You Know?" + Environment.NewLine + quote);
                    Console.WriteLine(Environment.NewLine + "Do You Know?" + Environment.NewLine + quote +
                                      Environment.NewLine);
                }
                else
                {
                    greetings.WriteLine("Do You Know?" + Environment.NewLine +
                                    "The Blue Screen Of Death which is produced by Windows is a way to protect your data from corruption. " +
                                    Environment.NewLine +
                                    "Windows has got some serious rules to protect your data ;)");
                }
                
                greetings.WriteLine(Environment.NewLine + Environment.NewLine +
                                    "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~EOF~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");

            }

            while (msinfoThread.IsAlive)
            {
                Console.WriteLine(DateTime.Now.ToString("G") + Environment.NewLine +
                                  "\t - Processing MSINFO32 Report. Kindly do not close app...\n");
                Thread.Sleep(8000);
            }
            Console.WriteLine(DateTime.Now.ToString("G") + "\t - Zipping Up Files!");
            ZipFile.CreateFromDirectory(tempDirectory,
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory) + @"\" + zipFileName,
                CompressionLevel.Optimal, false);
            var greetingsProcess = Process.Start(tempDirectory + @"\greetings.txt");
            Thread.Sleep(1000);
            if (greetingsProcess!=null)
            {
                FlashWindow(greetingsProcess.MainWindowHandle, false);
            }
        }



        static void MsinfoReportThread()
        {
            string tempDirectory = Path.GetTempPath() + @"blueelvis";
            using (Process msinfoNfoReport = new Process())
            {
                if (File.Exists(Environment.SystemDirectory + @"\msinfo32.exe"))
                {
                    Console.WriteLine(Environment.NewLine + Environment.NewLine + DateTime.Now.ToString("G") +
                                      "\t - Generating MSINFO32 Report" + Environment.NewLine);
                    msinfoNfoReport.StartInfo.FileName = Environment.SystemDirectory + @"\msinfo32.exe";
                    msinfoNfoReport.StartInfo.Arguments = @"/nfo " + "\"" + tempDirectory + @"\MSINFO32.NFO" + "\"";
                    msinfoNfoReport.Start();
                    msinfoNfoReport.WaitForExit();
                    msinfoNfoReport.Close();
                }
                else
                {
                    Console.WriteLine("MSINFO32.exe not found in system");
                }
            }
        }

       static string Quotes()
        {
            WebClient quoteWebClient = new WebClient();
            try
            {
                string quoteString = quoteWebClient.DownloadString("https://omgdebugging.com/quote.php");
                return quoteString == "0" ? "0" : quoteString;
            }
            catch (Exception)
            {
                return "0";
            }
        }
        static string ConvertDateTime(string stringDateToConvert)
        {
            stringDateToConvert = stringDateToConvert.Replace("\r", "").Replace("\n", "");
            if (stringDateToConvert.Length > 8)
                stringDateToConvert = stringDateToConvert.Remove(8);

            var temporaryArray = stringDateToConvert.ToCharArray();
            var output = temporaryArray[0].ToString() + temporaryArray[1].ToString() + temporaryArray[2].ToString() + temporaryArray[3].ToString() + "-";
            output += temporaryArray[4].ToString() + temporaryArray[5].ToString() + "-";
            output += temporaryArray[6].ToString() + temporaryArray[7].ToString();

            return output;
        }


    }
}
