using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Authentication;

namespace Decos.Http.Signatures.Validation.AspNetCore
{
    public class SignatureOptions : AuthenticationSchemeOptions
    {
        public string AuthenticationScheme { get; set; } = SignatureDefaults.AuthenticationScheme;
    }
}
