using Aes.AF.Extensions;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Aes.AF
{
    public class AesSettings
    {
        public const string AesSettingsEnvPath = "AesSettingsEnvPath";
        public EncryptModeEnum Mode { get; private set; } = EncryptModeEnum.ECB;

        public string Key { get; private set; } = "";

        private byte[] iv;
        public byte[] IV
        {
            get
            {
                byte[] target = new byte[iv.Length];
                Array.Copy(iv, target, target.Length);
                return target;
            }
            private set
            {
                iv = new byte[value.Length];
                Array.Copy(value, iv, iv.Length);
            }
        }
        public AesKeySize KeySize { get; private set; } = AesKeySize.Aes128;
        public PaddingMode PaddingMode { get; private set; } = PaddingMode.PKCS7;

        public bool KeyIsBase64 { get; private set; } = false;

        public FeedbackSizeEnum FeedbackSize { get; private set; }

#if NET6_0
        public static IEnumerable<AesSettings> GetEnumerator()
        {
            var builder = new ConfigurationBuilder().AddJsonFile(GetAesSettingsEnvPath, optional: false, reloadOnChange: true);
            IConfiguration configuration = builder.Build();

            return configuration
                .GetSection("AesSettings")
                .GetChildren()
                .Select(s => Create(s));
        }
#endif

        public byte[] GetKey()
            => KeyIsBase64? Convert.FromBase64String(Key) : Key.GetKey(KeySize);

        public static AesSettings Create(IConfigurationSection section)
        {
            EncryptModeEnum mode = section["Mode"].ToEnum<EncryptModeEnum>();
            switch (mode)
            {
                case EncryptModeEnum.ECB:
                    return CreateEcb(section);
                case EncryptModeEnum.CFB:
                    return CreateFeedback(section);
                case EncryptModeEnum.CBC:
                case EncryptModeEnum.CTR:
                case EncryptModeEnum.GCM:
                case EncryptModeEnum.OFB:
                    return CreateDefault(section);
                default:
                    throw new ArgumentOutOfRangeException($"Argumendt {mode}");
            }
        }

        public static AesSettings Create(EncryptModeEnum mode, string key, string iv,
            AesKeySize keySize = AesKeySize.Aes256,
            PaddingMode paddingMode = PaddingMode.PKCS7,
            bool keyIsBase64 = true,
            FeedbackSizeEnum feedbackSize = FeedbackSizeEnum.Eight)
            => new AesSettings()
            {
                Mode = mode,
                Key = key,
                IV = Convert.FromBase64String(iv),
                KeySize = keySize,
                PaddingMode = paddingMode,
                KeyIsBase64 = keyIsBase64,
                FeedbackSize = feedbackSize
            };

        private static AesSettings CreateEcb(IConfigurationSection section)
            => new AesSettings()
            {
                Mode = section["Mode"].ToEnum<EncryptModeEnum>(),
                Key = section["Key"],
                KeySize = section["KeySize"].ToEnum<AesKeySize>(),
                PaddingMode = section["PaddingMode"] != null ? section["PaddingMode"].ToEnum<PaddingMode>() : PaddingMode.PKCS7,
                KeyIsBase64 = section["KeyIsBase64"] != null ? Convert.ToBoolean(section["KeyIsBase64"]) : false
            };

        private static AesSettings CreateFeedback(IConfigurationSection section)
            => new AesSettings()
            {
                Mode = section["Mode"].ToEnum<EncryptModeEnum>(),
                Key = section["Key"],
                IV = Convert.FromBase64String(section["IV"]),
                KeySize = section["KeySize"].ToEnum<AesKeySize>(),
                KeyIsBase64 = section["KeyIsBase64"] != null ? Convert.ToBoolean(section["KeyIsBase64"]) : false,
                FeedbackSize = section["FeedbackSize"].ToEnum<FeedbackSizeEnum>()
            };

        private static AesSettings CreateDefault(IConfigurationSection section)
            => new AesSettings()
            {
                Mode = section["Mode"].ToEnum<EncryptModeEnum>(),
                Key = section["Key"],
                IV = Convert.FromBase64String(section["IV"]),
                KeySize = section["KeySize"].ToEnum<AesKeySize>(),
                PaddingMode = section["PaddingMode"] != null ? section["PaddingMode"].ToEnum<PaddingMode>() : PaddingMode.PKCS7,
                KeyIsBase64 = section["KeyIsBase64"] != null ? Convert.ToBoolean(section["KeyIsBase64"]) : false
            };

        private static string GetAesSettingsEnvPath { get => Environment.GetEnvironmentVariable(AesSettingsEnvPath) ?? "Configs\\AesSettings.json"; }
    }
}
