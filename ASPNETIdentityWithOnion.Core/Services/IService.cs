using System;
using ASPNETIdentityWithOnion.Core.Data;

namespace ASPNETIdentityWithOnion.Core.Services
{
    public interface IService : IDisposable
    {
        IUnitOfWork UnitOfWork { get; }
    }
}
