using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Reflection;
using Fclp;
using Fclp.Internals.Extensions;
using Fclp.Internals.Errors;
using Fclp.Internals.Parsing;
using Fclp.Internals.Validators;
using System.Management.Automation;
using System.Security.Cryptography;


namespace ExeToPosh
{
    class LoaderProperties
    {
        public  int MTAMode = 0;
        public bool bOneInstance = false;
        public bool Restricted = false;
        public bool HighEncryption = false;
        private const int RUNFLAG_NORMAL = 0;
        private const int RUNFLAG_STA = 1;
        private const int RUNFLAG_RESTRICTED = 2;
        private const int RUNFLAG_SINGLEINST = 4;
        private const int RUNFLAG_WINDOWS = 16;
        private const int RUNFLAG_UNENCRYPTED = 256;
        private const int RUNFLAG_HIGHENCRYPTION = 512;
        public string szTitle;
        public string InitialFolder;
        public string COMObjectPath;
        public string strEngine;
        public bool LeaveDataFiles;
        public bool LeaveScriptFiles;
        public bool LeaveCOMObjects;
        public bool RunParallel;
        public int FolderSettings;
        public string UserID;
        public string Password;
        public int LoginMethod;
        public int TrialMode;
        public int RunFlags;
        public int package_day;
        public int package_month;
        public int package_year;
        public string EngineParameters;
        public string AllowedOSVersions;
        public string RestrictedUser;
        public string RestrictedMachines;
        public string RestrictedMAC;
        public string RestrictedDomain;
    }

    public class ApplicationArguments
    {
        public string InFile { get; set; }
        public string OutFile { get; set; }
        public bool Silent { get; set; }
    }

    class Program
    {

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("Kernel32.dll")]
        public static extern IntPtr FindResource(IntPtr hModule, IntPtr lpid, IntPtr lpType);

        [DllImport("Kernel32.dll")]
        public static extern IntPtr LoadResource(IntPtr hModule, IntPtr hResInfo);

        [DllImport("Kernel32.dll")]
        public static extern IntPtr LockResource(IntPtr hResInfo);

        [DllImport("Kernel32.dll")]
        public static extern uint SizeofResource(IntPtr hModule, IntPtr hResInfo);

        [DllImport("Kernel32.dll")]
        public static extern bool FreeResource(IntPtr hglbResource);

        public static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] salt = passwordBytes;
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
                {
                    rijndaelManaged.KeySize = 256;
                    rijndaelManaged.BlockSize = 128;
                    Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passwordBytes, salt, 1000);
                    rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.KeySize / 8);
                    rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.BlockSize / 8);
                    rijndaelManaged.Mode = CipherMode.CBC;
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, rijndaelManaged.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cryptoStream.Close();
                    }
                    return memoryStream.ToArray();
                }
            }
        }

        public static int GetSaltSize(byte[] passwordBytes)
        {
            byte[] bytes = new Rfc2898DeriveBytes(passwordBytes, passwordBytes, 1000).GetBytes(2);
            StringBuilder stringBuilder = new StringBuilder();
            for (int index = 0; index < bytes.Length; ++index)
                stringBuilder.Append(Convert.ToInt32(bytes[index]).ToString());
            int num1 = 0;
            foreach (char ch in stringBuilder.ToString())
            {
                int num2 = Convert.ToInt32(ch.ToString());
                num1 += num2;
            }
            return num1;
        }

        public static string Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);
            byte[] numArray = AES_Decrypt(bytesToBeDecrypted, passwordBytes);
            int saltSize = GetSaltSize(passwordBytes);
            byte[] bytes = new byte[numArray.Length - saltSize];
            for (int index = saltSize; index < numArray.Length; ++index)
                bytes[index - saltSize] = numArray[index];
            return Encoding.UTF8.GetString(bytes);
        }

        private static unsafe byte[] GetPasswordBytes(SecureString secure)
        {
            byte[] buffer = (byte[])null;
            IntPtr s = Marshal.SecureStringToGlobalAllocAnsi(secure);
            try
            {
                byte* numPtr1 = (byte*)s.ToPointer();
                byte* numPtr2 = numPtr1;
                do
                    ;
                while ((int)*numPtr2++ != 0);
                int length = (int)(numPtr2 - numPtr1 - 1L);
                buffer = new byte[length];
                for (int index = 0; index < length; ++index)
                {
                    byte num = numPtr1[index];
                    buffer[index] = num;
                }
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocAnsi(s);
            }
            return SHA256.Create().ComputeHash(buffer);
        }

        public static byte[] SimpleDecodeData(byte[] text, int size, byte[] key)
        {
            byte[] numArray = new byte[size];
            int index = 0;
            uint num1 = 0U;
            while ((long)num1 < (long)size)
            {
                byte num2 = text[num1];
                byte num3 = key[index];
                if ((int)num3 == 0)
                {
                    index = 0;
                    num3 = key[index];
                }
                byte num4 = (byte)((uint)(byte)((uint)num2 + 106U) - (uint)num3);
                if ((int)(num1 % 5U) != 0)
                    num4 += (byte)2;
                if ((int)(num1 % 7U) != 0)
                    num4 -= (byte)9;
                if ((int)(num1 % 3U) != 0)
                    num4 += (byte)3;
                byte num5 = (byte)((uint)~num4 - 27U);
                numArray[num1] = num5;
                ++num1;
                ++index;
            }
            return numArray;
        }

        public static unsafe LoaderProperties LoadProperties(Assembly ass)
        {
            IntPtr hModule = Marshal.GetHINSTANCE(ass.GetModules()[0]);
            LoaderProperties PowerShellLoader = new LoaderProperties();
            IntPtr resource = FindResource(hModule, new IntPtr(1), new IntPtr(10));
            uint num = SizeofResource(hModule, resource);
            byte[] numArray1 = new byte[num];
            byte[] numArray2 = new byte[512];
            Marshal.Copy(LockResource(LoadResource(hModule, resource)), numArray1, 0, (int)num);
            PowerShellLoader.LeaveDataFiles = (int)numArray1[1816] != 0;
            PowerShellLoader.LeaveScriptFiles = (int)numArray1[1820] != 0;
            PowerShellLoader.LeaveCOMObjects = (int)numArray1[1824] != 0;
            PowerShellLoader.RunParallel = (int)numArray1[1828] != 0;
            PowerShellLoader.FolderSettings = BitConverter.ToInt32(numArray1, 1832);
            PowerShellLoader.LoginMethod = BitConverter.ToInt32(numArray1, 2092);
            PowerShellLoader.TrialMode = BitConverter.ToInt32(numArray1, 2096);
            PowerShellLoader.RunFlags = BitConverter.ToInt32(numArray1, 2100);
            if ((PowerShellLoader.RunFlags & 1) == 1)
                PowerShellLoader.MTAMode |= 1;
            if ((PowerShellLoader.RunFlags & 4) == 4)
                PowerShellLoader.bOneInstance = true;
            if ((PowerShellLoader.RunFlags & 2) == 2)
                PowerShellLoader.Restricted = true;
            if ((PowerShellLoader.RunFlags & 512) == 512)
                PowerShellLoader.HighEncryption = true;
            PowerShellLoader.package_day = BitConverter.ToInt32(numArray1, 2104);
            PowerShellLoader.package_month = BitConverter.ToInt32(numArray1, 2108);
            fixed (byte* numPtr = &numArray1[2112])
                PowerShellLoader.package_year = *(int*)numPtr;
            PowerShellLoader.szTitle = Encoding.Unicode.GetString(numArray1);
            int length1 = PowerShellLoader.szTitle.IndexOf(char.MinValue);
            if (length1 != -1)
                PowerShellLoader.szTitle = PowerShellLoader.szTitle.Substring(0, length1);
            Array.Copy((Array)numArray1, 256, (Array)numArray2, 0, 512);
            PowerShellLoader.InitialFolder = Encoding.Unicode.GetString(numArray2);
            int length2 = PowerShellLoader.InitialFolder.IndexOf(char.MinValue);
            if (length2 != -1)
                PowerShellLoader.InitialFolder = PowerShellLoader.InitialFolder.Substring(0, length2);
            Array.Copy((Array)numArray1, 776, (Array)numArray2, 0, 512);
            PowerShellLoader.COMObjectPath = Encoding.Unicode.GetString(numArray2);
            int length3 = PowerShellLoader.COMObjectPath.IndexOf(char.MinValue);
            if (length3 != -1)
                PowerShellLoader.COMObjectPath = PowerShellLoader.COMObjectPath.Substring(0, length3);
            Array.Copy((Array)numArray1, 1296, (Array)numArray2, 0, 512);
            PowerShellLoader.strEngine = Encoding.Unicode.GetString(numArray2);
            int length4 = PowerShellLoader.strEngine.IndexOf(char.MinValue);
            if (length4 != -1)
                PowerShellLoader.strEngine = PowerShellLoader.strEngine.Substring(0, length4);
            Array.Copy((Array)numArray1, 1836, (Array)numArray2, 0, 128);
            PowerShellLoader.UserID = Encoding.Unicode.GetString(numArray2);
            int length5 = PowerShellLoader.UserID.IndexOf(char.MinValue);
            if (length5 != -1)
                PowerShellLoader.UserID = PowerShellLoader.UserID.Substring(0, length5);
            Array.Copy((Array)numArray1, 1964, (Array)numArray2, 0, 128);
            byte[] key = new byte[7]
              {
                (byte) 102,
                (byte) 111,
                (byte) 111,
                (byte) 98,
                (byte) 97,
                (byte) 114,
                (byte) 0
              };

            PowerShellLoader.Password = Encoding.Unicode.GetString(SimpleDecodeData(numArray2, 128, key));
            int length6 = PowerShellLoader.Password.IndexOf(char.MinValue);
            if (length6 != -1)
                PowerShellLoader.Password = PowerShellLoader.Password.Substring(0, length6);
            Array.Copy((Array)numArray1, 2116, (Array)numArray2, 0, 512);
            PowerShellLoader.EngineParameters = Encoding.Unicode.GetString(numArray2);
            int length7 = PowerShellLoader.EngineParameters.IndexOf(char.MinValue);
            if (length7 != -1)
                PowerShellLoader.EngineParameters = PowerShellLoader.EngineParameters.Substring(0, length7);
            Array.Copy((Array)numArray1, 2636, (Array)numArray2, 0, 512);
            PowerShellLoader.AllowedOSVersions = Encoding.Unicode.GetString(numArray2);
            int length8 = PowerShellLoader.AllowedOSVersions.IndexOf(char.MinValue);
            if (length8 != -1)
                PowerShellLoader.AllowedOSVersions = PowerShellLoader.AllowedOSVersions.Substring(0, length8);
            Array.Copy((Array)numArray1, 3156, (Array)numArray2, 0, 512);
            PowerShellLoader.RestrictedUser = Encoding.Unicode.GetString(numArray2);
            int length9 = PowerShellLoader.RestrictedUser.IndexOf(char.MinValue);
            if (length9 != -1)
                PowerShellLoader.RestrictedUser = PowerShellLoader.RestrictedUser.Substring(0, length9);
            Array.Copy((Array)numArray1, 3676, (Array)numArray2, 0, 512);
            PowerShellLoader.RestrictedMachines = Encoding.Unicode.GetString(numArray2);
            int length10 = PowerShellLoader.RestrictedMachines.IndexOf(char.MinValue);
            if (length10 != -1)
                PowerShellLoader.RestrictedMachines = PowerShellLoader.RestrictedMachines.Substring(0, length10);
            Array.Copy((Array)numArray1, 4196, (Array)numArray2, 0, 512);
            PowerShellLoader.RestrictedMAC = Encoding.Unicode.GetString(numArray2);
            int length11 = PowerShellLoader.RestrictedMAC.IndexOf(char.MinValue);
            if (length11 != -1)
                PowerShellLoader.RestrictedMAC = PowerShellLoader.RestrictedMAC.Substring(0, length11);
            Array.Copy((Array)numArray1, 4716, (Array)numArray2, 0, 512);
            PowerShellLoader.RestrictedDomain = Encoding.Unicode.GetString(numArray2);
            int length12 = PowerShellLoader.RestrictedDomain.IndexOf(char.MinValue);
            if (length12 != -1)
                PowerShellLoader.RestrictedDomain = PowerShellLoader.RestrictedDomain.Substring(0, length12);
            FreeResource(resource);

            return PowerShellLoader;
        }

        static int Main(string[] args)
        {
            var p = new FluentCommandLineParser<ApplicationArguments>();

            // specify which property the value will be assigned too.
            p.Setup(arg => arg.InFile)
            .As(CaseType.CaseInsensitive, "i", "InFile")
            .WithDescription("Input filename (.exe)")
            .Required();

            p.Setup(arg => arg.OutFile)
             .As(CaseType.CaseInsensitive, "o", "OutFile")
            .WithDescription("Output filename (.ps1)")
            .Required();

            p.Setup(arg => arg.Silent)
            .As(CaseType.CaseInsensitive, "s", "Silent")
            .WithDescription("No output");

            p.SetupHelp("?", "help")
            .Callback(text => Console.WriteLine("Convert a PowerShell Executable (.exe) back to PowerShell (.ps1).\n" + text));

            var result = p.Parse(args);
            if (result.HasErrors)
            {
                p.HelpOption.ShowHelp(p.Options);
                return 1;
            }

            var exe = p.Object.InFile;

            if (!p.Object.Silent)
            {
                Console.WriteLine("ExeToPosh 0.2 written by Remko Weijnen");

                Console.WriteLine("Input file: {0}", p.Object.InFile);
                Console.WriteLine("Output file: {0}", p.Object.OutFile);
            }

            String prettyCommand = "";
            String filename = p.Object.OutFile;
           
            Assembly ass = Assembly.LoadFile(Path.GetFullPath(exe));
            Type asmType;
            asmType = ass.GetType("_32._88");
            if (asmType != null)
            {
                if (!p.Object.Silent)
                {
                    Console.WriteLine("Packer: ISESteroids");
                }

                string str = Guid.NewGuid().ToString();
                Environment.SetEnvironmentVariable("zumsel", str, EnvironmentVariableTarget.Process);

                MethodInfo GetScriptBlock = asmType.GetMethod("_46", BindingFlags.NonPublic | BindingFlags.Static);
                var parameters = new object[] { str };
                try
                {
                    var scriptBlock = (ScriptBlock)GetScriptBlock.Invoke(null, parameters);
                    prettyCommand = scriptBlock.Ast.Extent.Text;
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Exception while unpacking: {0}", ex.Message);
                }


            }
            else
            {
                asmType = ass.GetType("SAPIENPowerShellHost.PowerShellLoader");
                if (asmType == null)
                {
   
                    asmType = asmType = ass.GetType("PoshExeHostCmd.Program");
                   
                    if (asmType == null)
                    {
                        if (!p.Object.Silent)
                        {
                            Console.WriteLine("Packer: Sapien (PowerShell Studio) variant 3");
                        }
                    }
                    else if (!p.Object.Silent)
                    {
                        Console.WriteLine("Packer: Sapien (PowerShell Studio) variant 2");
                    }
                }
                else
                {
                    Console.WriteLine("Packer: Sapien (PowerShell Studio) variant 1");
                }

                LoaderProperties loader = LoadProperties(ass);
                if (!p.Object.Silent)
                {
                    Console.WriteLine("Title: {0}", loader.szTitle);
                    Console.WriteLine("Engine: {0}", loader.strEngine);
                    Console.WriteLine("Engine Parameters: {0}", loader.strEngine);
                    Console.WriteLine("High Encryption: {0}", loader.HighEncryption);
                    Console.WriteLine("Password: {0}", loader.Password);
                }

                //MethodInfo GetPasswordBytes = asmType.GetMethod("GetPasswordBytes", BindingFlags.NonPublic | BindingFlags.Static);
//                MethodInfo Decrypt = asmType.GetMethod("Decrypt", BindingFlags.Public | BindingFlags.Static);
//                MethodInfo SimpleDecodeData = asmType.GetMethod("SimpleDecodeData", BindingFlags.Public | BindingFlags.Static);

                IntPtr hModule = Marshal.GetHINSTANCE(ass.GetModules()[0]);
                IntPtr resource = FindResource(hModule, new IntPtr(4), new IntPtr(10));
                uint num2 = SizeofResource(hModule, resource);
                byte[] numArray = new byte[num2];
                Marshal.Copy(LockResource(LoadResource(hModule, resource)), numArray, 0, (int)num2);
                string command;

                if (!loader.HighEncryption)
                {
                    Encoding encoding = Encoding.GetEncoding(1252);
                    byte[] key = new byte[13]
              {
                (byte) 104,
                (byte) 115,
                (byte) 100,
                (byte) 105,
                (byte) 97,
                (byte) 102,
                (byte) 119,
                (byte) 105,
                (byte) 117,
                (byte) 101,
                (byte) 114,
                (byte) 97,
                (byte) 0
              };
                    byte[] bytes = SimpleDecodeData(numArray, (int)num2, key);
                    command = (int)bytes[0] != (int)byte.MaxValue || (int)bytes[1] != 254 ? ((int)bytes[0] != 239 || (int)bytes[1] != 187 || (int)bytes[2] != 191 ? encoding.GetString(bytes) : Encoding.UTF8.GetString(bytes).Substring(1)) : Encoding.Unicode.GetString(bytes).Substring(1);
                }
                else
                {
                    SecureString secure = new SecureString();
                    secure.AppendChar('h');
                    secure.AppendChar('s');
                    secure.AppendChar('d');
                    secure.AppendChar('i');
                    secure.AppendChar('a');
                    secure.AppendChar('f');
                    secure.AppendChar('w');
                    secure.AppendChar('i');
                    secure.AppendChar('u');
                    secure.AppendChar('e');
                    secure.AppendChar('r');
                    secure.AppendChar('a');
                    var parameters = new object[] { secure };
                    var passwordBytes = GetPasswordBytes(secure);

                    parameters = new object[] { numArray, passwordBytes };
                    command = Decrypt(numArray, passwordBytes);
                }
                //char tab = '\u0009';

                prettyCommand = command.Replace(@"\r\n", System.Environment.NewLine).Replace("\t", "  ");
            }

            File.WriteAllText(filename, prettyCommand);

            if (!p.Object.Silent)
            {
                Console.WriteLine("finished.");
            }

            return 0;
        }
    }
}
