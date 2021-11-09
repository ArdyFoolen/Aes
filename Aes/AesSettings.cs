using Aes.AF.Extensions;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Aes.AF
{
    public class AesSettings
    {
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

        public static IEnumerable<AesSettings> GetEnumerator()
        {
            var builder = new ConfigurationBuilder().AddJsonFile("Configs\\AesSettings.json", optional: false, reloadOnChange: true);
            IConfiguration configuration = builder.Build();

            return configuration
                .GetSection("AesSettings")
                .GetChildren()
                .Select(s => Create(s));
        }

        private static AesSettings Create(IConfigurationSection section)
        {
            EncryptModeEnum mode = section["Mode"].ToEnum<EncryptModeEnum>();
            switch (mode)
            {
                case EncryptModeEnum.ECB:
                    return CreateEcb(section);
                case EncryptModeEnum.CBC:
                case EncryptModeEnum.CTR:
                case EncryptModeEnum.GCM:
                    return CreateDefault(section);
                default:
                    throw new ArgumentOutOfRangeException($"Argumendt {mode}");
            }
        }

        private static AesSettings CreateEcb(IConfigurationSection section)
            => new AesSettings()
            {
                Mode = section["Mode"].ToEnum<EncryptModeEnum>(),
                Key = section["Key"],
                KeySize = section["KeySize"].ToEnum<AesKeySize>()
            };

        private static AesSettings CreateDefault(IConfigurationSection section)
            => new AesSettings()
            {
                Mode = section["Mode"].ToEnum<EncryptModeEnum>(),
                Key = section["Key"],
                IV = Convert.FromBase64String(section["IV"]),
                KeySize = section["KeySize"].ToEnum<AesKeySize>()
            };
    }
}
