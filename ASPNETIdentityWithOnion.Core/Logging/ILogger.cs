using System;

namespace ASPNETIdentityWithOnion.Core.Logging
{
    public interface ILogger
    {
        void Log(string message);
        void Log(Exception ex);
    }
}
