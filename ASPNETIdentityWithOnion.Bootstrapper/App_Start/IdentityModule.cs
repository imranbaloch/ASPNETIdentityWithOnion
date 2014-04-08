using System.Data.Entity;
using System.Web;
using ASPNETIdentityWithOnion.Core.Identity;
using ASPNETIdentityWithOnion.Data;
using ASPNETIdentityWithOnion.Data.Identity;
using ASPNETIdentityWithOnion.Data.Identity.Models;
using Autofac;
using Autofac.Integration.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

namespace ASPNETIdentityWithOnion.Bootstrapper
{
    public class IdentityModule : Module
    {
        protected override void Load(ContainerBuilder builder)
        {
            builder.RegisterType(typeof(ApplicationUserManager)).As(typeof(IApplicationUserManager)).InstancePerHttpRequest();
            builder.RegisterType(typeof(ApplicationRoleManager)).As(typeof(IApplicationRoleManager)).InstancePerHttpRequest();
            builder.RegisterType(typeof(ApplicationIdentityUser)).As(typeof(IUser<int>)).InstancePerHttpRequest();
            builder.Register(b => b.Resolve<IEntitiesContext>() as DbContext).InstancePerHttpRequest();
            builder.Register(b =>
            {
                var manager = IdentityFactory.CreateUserManager(b.Resolve<DbContext>());
                if (Startup.DataProtectionProvider != null)
                {
                    manager.UserTokenProvider =
                        new DataProtectorTokenProvider<ApplicationIdentityUser, int>(
                            Startup.DataProtectionProvider.Create("ASP.NET Identity"));
                }
                return manager;
            }).InstancePerHttpRequest();
            builder.Register(b => IdentityFactory.CreateRoleManager(b.Resolve<DbContext>())).InstancePerHttpRequest();
            builder.Register(b => HttpContext.Current.GetOwinContext().Authentication).InstancePerHttpRequest();
        }
    }
}
