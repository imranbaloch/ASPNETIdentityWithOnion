using System.Collections.Generic;
using System.Threading.Tasks;
using ASPNETIdentityWithOnion.Core.DomainModels.Identity;
using System;

namespace ASPNETIdentityWithOnion.Core.Identity
{
    public interface IApplicationRoleManager :IDisposable
    {
        Task<ApplicationIdentityResult> CreateAsync(ApplicationRole role);
        ApplicationIdentityResult Create(ApplicationRole role);
        Task<ApplicationIdentityResult> DeleteAsync(int roleId);
        Task<ApplicationRole> FindByIdAsync(int roleId);
        ApplicationRole FindByName(string roleName);
        Task<ApplicationRole> FindByNameAsync(string roleName);
        IEnumerable<ApplicationRole> GetRoles();
        Task<IEnumerable<ApplicationRole>> GetRolesAsync();
        Task<bool> RoleExistsAsync(string roleName);
        Task<ApplicationIdentityResult> UpdateAsync(int roleId, string roleName);
    }
}