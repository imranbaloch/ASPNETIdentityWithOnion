using System;
using System.Collections.Generic;

namespace ASPNETIdentityWithOnion.Core.DomainModels.Identity
{
    public class AppUser
    {
        public AppUser()
        {
            Claims = new List<ApplicationUserClaim>();
            Roles = new List<ApplicationUserRole>();
            Logins = new List<ApplicationUserLogin>();
        }
        public virtual int AccessFailedCount { get; set; }
        public virtual ICollection<ApplicationUserClaim> Claims { get; private set; }
        public virtual string Email { get; set; }
        public virtual bool EmailConfirmed { get; set; }
        public virtual int Id { get; set; }
        public virtual bool LockoutEnabled { get; set; }
        public virtual DateTime? LockoutEndDateUtc { get; set; }
        public virtual ICollection<ApplicationUserLogin> Logins { get; private set; }
        public virtual string PasswordHash { get; set; }
        public virtual string PhoneNumber { get; set; }
        public virtual bool PhoneNumberConfirmed { get; set; }
        public virtual ICollection<ApplicationUserRole> Roles { get; private set; }
        public virtual string SecurityStamp { get; set; }
        public virtual bool TwoFactorEnabled { get; set; }
        public virtual string UserName { get; set; }
    }
}
