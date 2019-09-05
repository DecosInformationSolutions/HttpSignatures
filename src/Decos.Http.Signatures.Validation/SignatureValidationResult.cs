using System;

namespace Decos.Http.Signatures.Validation
{
    public enum SignatureValidationResult
    {
        OK = 0,
        Invalid = 1,
        Expired = 2,
        Duplicate = 3,
    }
}