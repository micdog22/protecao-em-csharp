// Verificação de assinatura Authenticode via WinVerifyTrust (Windows)
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace SecureApp.Guard
{
    public readonly struct VerificationResult
    {
        public bool Success { get; }
        public int StatusCode { get; }
        public string Message { get; }
        public string Subject { get; }
        public string Issuer { get; }
        public bool MatchesAllowedPublisher { get; }

        public VerificationResult(bool success, int statusCode, string message, string subject, string issuer, bool matchesAllowedPublisher)
        {
            Success = success;
            StatusCode = statusCode;
            Message = message;
            Subject = subject;
            Issuer = issuer;
            MatchesAllowedPublisher = matchesAllowedPublisher;
        }
    }

    public static class SignatureVerifier
    {
        // {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid(0x00aac56b, 0xcd44, 0x11d0, 0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee);

        public static VerificationResult Verify(string filePath, string[] allowedPublisherCn)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                throw new ArgumentNullException(nameof(filePath));

            if (!System.IO.File.Exists(filePath))
                return new VerificationResult(false, unchecked((int)0x80070002), "Arquivo não encontrado.", "", "", false);

            int status = (int)WinVerifyTrustForFile(filePath);
            bool ok = status == 0;
            string subject = "";
            string issuer = "";
            bool allowed = false;

            if (ok)
            {
                try
                {
                    // Obtém o certificado do assinante (para log/checagem do CN).
                    var cert = X509Certificate.CreateFromSignedFile(filePath);
                    var cert2 = new X509Certificate2(cert);
                    subject = cert2.Subject ?? "";
                    issuer  = cert2.Issuer ?? "";

                    if (allowedPublisherCn != null && allowedPublisherCn.Length > 0)
                    {
                        allowed = allowedPublisherCn.Any(allow =>
                            !string.IsNullOrWhiteSpace(allow) &&
                            subject.IndexOf(allow, StringComparison.OrdinalIgnoreCase) >= 0);
                    }
                }
                catch (Exception ex)
                {
                    return new VerificationResult(false, unchecked((int)0x8009200D), "Falha ao ler certificado: " + ex.Message, "", "", false);
                }
            }

            string msg = ok ? "Assinatura válida." : GetErrorMessage(status);
            return new VerificationResult(ok, status, msg, subject, issuer, allowed);
        }

        private static uint WinVerifyTrustForFile(string filePath)
        {
            WINTRUST_FILE_INFO fileInfo = new WINTRUST_FILE_INFO(filePath);
            IntPtr pFile = IntPtr.Zero;
            IntPtr pData = IntPtr.Zero;

            try
            {
                pFile = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
                Marshal.StructureToPtr(fileInfo, pFile, false);

                WINTRUST_DATA data = new WINTRUST_DATA(pFile);
                pData = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_DATA)));
                Marshal.StructureToPtr(data, pData, false);

                return WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);
            }
            finally
            {
                if (pFile != IntPtr.Zero)
                {
                    Marshal.DestroyStructure<WINTRUST_FILE_INFO>(pFile);
                    Marshal.FreeHGlobal(pFile);
                }
                if (pData != IntPtr.Zero)
                {
                    Marshal.DestroyStructure<WINTRUST_DATA>(pData);
                    Marshal.FreeHGlobal(pData);
                }
            }
        }

        private static string GetErrorMessage(int status)
        {
            // 0x800B0100: NO_SIGNATURE
            // 0x800B0109: CERT_E_UNTRUSTEDROOT
            // 0x8009200D: CRYPT_E_BAD_MSG
            // etc.
            return $"WinVerifyTrust falhou (0x{status:X8}).";
        }

        // ==== P/Invoke e estruturas ====

        private const uint WTD_UI_NONE = 2;
        private const uint WTD_REVOKE_NONE = 0;
        private const uint WTD_CHOICE_FILE = 1;
        private const uint WTD_STATEACTION_IGNORE = 0;
        private const uint WTD_SAFER_FLAG = 0x00000100;
        private const uint WTD_REVOCATION_CHECK_NONE = 0x00000000;

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern uint WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, IntPtr pWVTData);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;

            public WINTRUST_FILE_INFO(string filePath)
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
                pcwszFilePath = filePath;
                hFile = IntPtr.Zero;
                pgKnownSubject = IntPtr.Zero;
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            [MarshalAs(UnmanagedType.LPWStr)] public string pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;

            public WINTRUST_DATA(IntPtr pFileInfo)
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
                pPolicyCallbackData = IntPtr.Zero;
                pSIPClientData = IntPtr.Zero;
                dwUIChoice = WTD_UI_NONE;
                fdwRevocationChecks = WTD_REVOKE_NONE;
                dwUnionChoice = WTD_CHOICE_FILE;
                pFile = pFileInfo;
                dwStateAction = WTD_STATEACTION_IGNORE;
                hWVTStateData = IntPtr.Zero;
                pwszURLReference = null!;
                dwProvFlags = WTD_SAFER_FLAG | WTD_REVOCATION_CHECK_NONE;
                dwUIContext = 0;
                pSignatureSettings = IntPtr.Zero;
            }
        }
    }
}
