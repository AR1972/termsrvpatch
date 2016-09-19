//
//=============================================================================//
//      This program is free software. It comes without any warranty, to       //
//       the extent permitted by applicable law. You can redistribute it       //
//      and/or modify it under the terms of the Do What The Fuck You Want      //
//       To Public License, Version 2, as published by Sam Hocevar. See        //
//              http://sam.zoy.org/wtfpl/COPYING for more details.             /
//=============================================================================//
//
using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.IO;
using System.ComponentModel;
using System.Security;
using System.Security.AccessControl;
using System.Diagnostics;

namespace termsrvpatch
{
    class termsrvpatch
    {
        static String s_md5 = null;
        static String TrustedInstaller = "NT SERVICE\\TrustedInstaller";
        static String UserName = Environment.UserName;

        //x86 RTM patch info

        static String x86_RTM_patched = "C468ADABA2040F6585FE04EA4C81984A";
        static String x86_RTM_unpatched = "A01E50A04D7B1960B33E92B9080E6A94";
        static int x86_RTM_patch0_offset = 0x18AF3;
        static int x86_RTM_patch1_offset = 0x19225;
        static int x86_RTM_patch2_offset = 0x668C5;

        //x64 RTM patch info

        static String x64_RTM_patched = "572F6C8D3726DB1D3D524A6BCE1C7EAB";
        static String x64_RTM_unpatched = "0F05EC2887BFE197AD82A13287D2F404";
        static int x64_RTM_patch0_offset = 0x170CC;
        static int x64_RTM_patch1_offset = 0x17396;
        static int x64_RTM_patch2_offset = 0x59ADE;

        //x86 SP1 patch info

        static String x86_SP1_patched = "FB2BB23032494A8515079B655FDCD686";
        static String x86_SP1_unpatched = "382C804C92811BE57829D8E550A900E2";
        static int x86_SP1_patch0_offset = 0x19153;
        static int x86_SP1_patch1_offset = 0x1989D;
        static int x86_SP1_patch2_offset = 0x655E5;

        //x64 SP1 patch info

        static String x64_SP1_patched = "E589BCD6041786C5E38E2D223C24C193";
        static String x64_SP1_unpatched = "2E648163254233755035B46DD7B89123";
        static int x64_SP1_patch0_offset = 0x17384;
        static int x64_SP1_patch1_offset = 0x176E2;
        static int x64_SP1_patch2_offset = 0x5A8AE;

        //x86 patch data

        static byte[] x86_patch0 = { 0xB8, 0x00, 0x01, 0x00, 0x00, 0x90, 0x89, 0x86, 0x20, 0x03, 0x00 };
        static byte[] x86_patch1 = { 0x90 };
        static byte[] x86_patch2 = { 0xEB };

        //x64 patch data

        static byte[] x64_patch0 = { 0xB8, 0x00, 0x01, 0x00, 0x00, 0x90, 0x89, 0x87, 0x38, 0x06, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
        static byte[] x64_patch1 = { 0x00 };
        static byte[] x64_patch2 = { 0xEB };

        //main

        public static int Main(string[] args)
        {
            Console.WriteLine("Windows 7 RTM / SP1 Concurrent Remote Desktop Sessions Patch");
            int ExitCode = 1;

            if (args.GetLength(0) != 1)
            {
                ShowUseage();
                return ExitCode;
            }

            String filetopatch = args[0].Replace("\"", "").Trim();

            if ((filetopatch.Length < 11) || (!filetopatch.Contains("termsrv.dll")))
            {
                ShowUseage();
                return ExitCode;
            }
            try
            {
                if (File.Exists(filetopatch))
                {
                    TakeOwnFile(filetopatch);
                    int patched = isPatched(filetopatch);
                    if (patched == 0)
                    {
                        int patch0_offset = 0;
                        int patch1_offset = 0;
                        int patch2_offset = 0;
                        int OSbits = 0;
                        byte[] patch0 = {};
                        byte[] patch1 = {};
                        byte[] patch2 = {};

                        if ((s_md5 == x86_SP1_patched) || (s_md5 == x86_RTM_patched) ||
                            (s_md5 == x86_SP1_unpatched) || (s_md5 == x86_RTM_unpatched))
                            OSbits = 32;

                        if ((s_md5 == x64_SP1_patched) || (s_md5 == x64_RTM_patched) ||
                            (s_md5 == x64_SP1_unpatched) || (s_md5 == x64_RTM_unpatched))
                            OSbits = 64;

                        byte[] aFileToPatch = File.ReadAllBytes(filetopatch);

                        if (OSbits == 32)
                        {
                            patch0 = x86_patch0;
                            patch1 = x86_patch1;
                            patch2 = x86_patch2;

                            if (s_md5 == x86_RTM_unpatched)
                            {
                                Console.WriteLine("found unpatched x86 RTM termsrv.dll");
                                patch0_offset = x86_RTM_patch0_offset;
                                patch1_offset = x86_RTM_patch1_offset;
                                patch2_offset = x86_RTM_patch2_offset;
                            }

                            if (s_md5 == x86_SP1_unpatched)
                            {
                                Console.WriteLine("found unpatched x86 SP1 termsrv.dll");
                                patch0_offset = x86_SP1_patch0_offset;
                                patch1_offset = x86_SP1_patch1_offset;
                                patch2_offset = x86_SP1_patch2_offset;
                            }
                        }
                        if (OSbits == 64)
                        {
                            patch0 = x64_patch0;
                            patch1 = x64_patch1;
                            patch2 = x64_patch2;

                            if (s_md5 == x64_RTM_unpatched)
                            {
                                Console.WriteLine("found unpatched x64 RTM termsrv.dll");
                                patch0_offset = x64_RTM_patch0_offset;
                                patch1_offset = x64_RTM_patch1_offset;
                                patch2_offset = x64_RTM_patch2_offset;
                            }

                            if (s_md5 == x64_SP1_unpatched)
                            {
                                Console.WriteLine("found unpatched x64 SP1 termsrv.dll");
                                patch0_offset = x64_SP1_patch0_offset;
                                patch1_offset = x64_SP1_patch1_offset;
                                patch2_offset = x64_SP1_patch2_offset;
                            }
                        }
                        Array.ConstrainedCopy(patch0, 0, aFileToPatch, patch0_offset, patch0.Length);
                        Array.ConstrainedCopy(patch1, 0, aFileToPatch, patch1_offset, patch1.Length);
                        Array.ConstrainedCopy(patch2, 0, aFileToPatch, patch2_offset, patch2.Length);

                        File.WriteAllBytes(filetopatch, aFileToPatch);
                        if (isPatched(filetopatch) == 1)
                        {
                            Console.WriteLine("patch successfully applied to " + filetopatch);
                            ExitCode = 0;
                        }
                        else
                        {
                            Console.WriteLine("patch unsuccessfully applied to " + filetopatch);
                        }
                        DateTime FileUTCTime = File.GetCreationTimeUtc(filetopatch);
                        File.SetLastWriteTime(filetopatch, FileUTCTime);
                    }
                    else if (patched == 1)
                    {
                    Console.WriteLine(filetopatch + " is already patched");
                    ExitCode = 0;
                    }
                    else if (patched == 2)
                    {
                    Console.WriteLine(filetopatch + " unknown checksum");
                    }
                }
                else
                {
                Console.WriteLine(filetopatch + " does not exist");
                }
                GiveOwnFile(filetopatch);
                return ExitCode;
            }
            catch(Exception ex)
            {
                Console.WriteLine("Main");
                Console.WriteLine(ex.Message);
                return ExitCode;
            }
        }

        //showuseage

        private static void ShowUseage()
        {
            Console.WriteLine();
            Console.WriteLine("Useage:");
            Console.WriteLine();
            Console.WriteLine("'path to termsrv.dll'");
            Console.WriteLine();
        }

        //ispatched

        private static int isPatched(String file)
        {
            try
            {
                s_md5 = CheckSumFile(file);
                if ((s_md5 == x86_SP1_patched) || (s_md5 == x64_SP1_patched) ||
                    (s_md5 == x86_RTM_patched) || (s_md5 == x64_RTM_patched))
                    return 1;
                else if ((s_md5 == x86_SP1_unpatched) || (s_md5 == x64_SP1_unpatched) ||
                         (s_md5 == x86_RTM_unpatched) || (s_md5 == x64_RTM_unpatched))
                    return 0;
                else
                    return 2;
            }
            catch (Exception ex)
            {
                Console.WriteLine("isPatched");
                Console.WriteLine(ex.Message);
                return 2;
            }
        }

        //checksumfile

        private static String CheckSumFile(String s_file)
        {
            try
            {
                if (System.IO.File.Exists(s_file))
                {
                    System.IO.FileStream infile = System.IO.File.OpenRead(s_file);
                    MD5 hasher = MD5.Create();
                    byte[] data =  hasher.ComputeHash(infile);
                    String s_data = System.BitConverter.ToString(data);
                    infile.Close();
                    infile.Dispose();
                    s_data = s_data.Replace("-", "");
                    return s_data;
                }
                else
                {
                    return null;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("CheckSumFile");
                Console.WriteLine(ex.Message);
                return null;
            }

        }

        //takeown

        private static void TakeOwnFile(String file)
        {
            try
            {
                if(File.Exists(file))
                {
                    Owner.ChangeOwner(file, UserName);
                    FileSecurity fSecurity = File.GetAccessControl(file);
                    FileSystemAccessRule accessRule = new FileSystemAccessRule(
                        UserName, FileSystemRights.FullControl, AccessControlType.Allow);
                    fSecurity.AddAccessRule(accessRule);
                    File.SetAccessControl(file, fSecurity);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("TakeOwnFile");
                Console.WriteLine(ex.Message);
            }
        }

        //giveown

        private static void GiveOwnFile(String file)
        {
            try
            {
                if (File.Exists(file))
                {
                    Owner.ChangeOwner(file, TrustedInstaller);
                    FileSecurity fSecurity = File.GetAccessControl(file);
                    FileSystemAccessRule accessRule = new FileSystemAccessRule(
                        UserName, FileSystemRights.FullControl, AccessControlType.Allow);
                    fSecurity.RemoveAccessRule(accessRule);
                    File.SetAccessControl(file, fSecurity);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("GiveOwnFile");
                Console.WriteLine(ex.Message);
            }
        }
    } //end class termsrvpatch

    public class Owner
    {
        private const int SE_FILE_OBJECT = 1;
        private const int OWNER_SECURITY_INFORMATION = 0x01;
        private const int NAME_SIZE = 64;
        private const int SID_SIZE = 32;

        [DllImport("advapi32.dll")]
        private static extern int SetNamedSecurityInfo(
            String pObjectName,
            int ObjectType,
            int SecurityInfo,
            IntPtr psidOwner,
            IntPtr psidGroup,
            IntPtr pDacl,
            IntPtr pSacl);

        [DllImport("advapi32.dll")]
        private static extern bool LookupAccountName(
            String lpSystemName,
            String lpAccountName,
            IntPtr Sid,
            ref int cbSid,
            String lpReferencedDomainNam,
            ref int cchRefrencedDomainName,
            ref IntPtr peUse);

        public static void ChangeOwner(String s_Path, String s_UserName)
        {
            IntPtr pNewOwner, peUse;
            Win32Exception Win32Error;
            String domain_name;
            int ret, sid_len, domain_len;

            if (Privileges.SetPrivileges() == false)
                throw new Exception("Required privilege not held by the user");

            sid_len = SID_SIZE;
            pNewOwner = Marshal.AllocHGlobal(sid_len);
            domain_len = NAME_SIZE;
            domain_name = String.Empty.PadLeft(domain_len);
            peUse = IntPtr.Zero;

            if (!LookupAccountName(null, s_UserName, pNewOwner, ref sid_len, domain_name, ref domain_len, ref peUse))
            {
                ret = Marshal.GetLastWin32Error();
                Win32Error = new Win32Exception(ret);
                throw new Exception(Win32Error.Message);
            }
            ret = SetNamedSecurityInfo(s_Path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, pNewOwner, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (ret != 0 )
            {
                Win32Error = new Win32Exception(ret);
                throw new Exception(Win32Error.Message);
            }
            Marshal.FreeHGlobal(pNewOwner);
        }
    }//end class Owner

    public class Privileges
    {
        [StructLayout(LayoutKind.Sequential, Pack=4)]
        private struct LUID_AND_ATTRIBUTES
        {
            public long Luid;
            public int Attributes;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        private struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            public LUID_AND_ATTRIBUTES Privilege1;
            public LUID_AND_ATTRIBUTES Privilege2;
        }

        [DllImport("advapi32.dll")]
        private static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            int DesiredAccess,
            ref IntPtr TokenHandle);

        [DllImport("advapi32.dll")]
        private static extern bool LookupPrivilegeValue(
            String lpSystemName,
            String lpName,
            ref long lpLuid);

        [DllImport("advapi32")]
        private static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle,
            bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState,
            int bufferLength,
            IntPtr PreviousState,
            IntPtr ReturnLength);

        const int TOKEN_QUERY = 0x08;
        const int TOKEN_ADJUST_PRIVILEGES = 0x20;
        const String SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";
        const String SE_RESTORE_NAME = "SeRestorePrivilege";
        const int SE_PRIVILEGE_ENABLED = 0x02;

        public static bool SetPrivileges()
        {
            IntPtr hProc, hToken;
            long luid_TakeOwnership, luid_Restore;
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();

            hProc = Process.GetCurrentProcess().Handle;
            hToken = IntPtr.Zero;

            if(!OpenProcessToken(hProc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref hToken))
                return false;

            luid_TakeOwnership = 0;

            if (!LookupPrivilegeValue(null, SE_TAKE_OWNERSHIP_NAME, ref luid_TakeOwnership))
                return false;

            luid_Restore = 0;

            if (!LookupPrivilegeValue(null, SE_RESTORE_NAME, ref luid_Restore))
                return false;

        tp.PrivilegeCount = 2;
        tp.Privilege1.Luid = luid_TakeOwnership;
        tp.Privilege1.Attributes = SE_PRIVILEGE_ENABLED;
        tp.Privilege2.Luid = luid_Restore;
        tp.Privilege2.Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
            return false;

        return true;
        }
    } //end class SetPrivilegs
}//end namspace termsrvpatch