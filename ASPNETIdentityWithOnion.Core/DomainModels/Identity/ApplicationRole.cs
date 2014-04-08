using System.Collections.Generic;

namespace ASPNETIdentityWithOnion.Core.DomainModels.Identity
{
    public class ApplicationRole
    {
        public ApplicationRole()
        {
            Users = new List<ApplicationUserRole>();
        }

        public int Id
        {
            get; set;
        }

        public virtual ICollection<ApplicationUserRole> Users{ get; private set; }

        public string Name { get; set; }
    }
}
