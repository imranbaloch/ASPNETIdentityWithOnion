using Microsoft.AspNet.Identity.EntityFramework;

namespace ASPNETIdentityWithOnion.Data.Identity.Models
{
    // You can add profile data for the user by adding more properties to your ApplicationIdentityUser class, please visit http://go.microsoft.com/fwlink/?LinkID=317594 to learn more.
    public class ApplicationIdentityUser :
        IdentityUser<int, ApplicationIdentityUserLogin, ApplicationIdentityUserRole, ApplicationIdentityUserClaim>
    {
    }


    public class ApplicationIdentityRole : IdentityRole<int, ApplicationIdentityUserRole>
    {
        public ApplicationIdentityRole()
        {
        }

        public ApplicationIdentityRole(string name)
        {
            Name = name;
        }
    }

    public class ApplicationIdentityUserRole : IdentityUserRole<int>
    {
    }

    public class ApplicationIdentityUserClaim : IdentityUserClaim<int>
    {
    }

    public class ApplicationIdentityUserLogin : IdentityUserLogin<int>
    {
    }

}