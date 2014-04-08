using System.Web.Mvc;
using ASPNETIdentityWithOnion.Bootstrapper;
using ASPNETIdentityWithOnion.Core.Data;
using ASPNETIdentityWithOnion.Core.Logging;
using ASPNETIdentityWithOnion.Core.Services;
using ASPNETIdentityWithOnion.Data;
using ASPNETIdentityWithOnion.Infrastructure.Logging;
using ASPNETIdentityWithOnion.Services;
using ASPNETIdentityWithOnion.Web;
using Autofac;
using Autofac.Integration.Mvc;

[assembly: WebActivatorEx.PreApplicationStartMethod(typeof(IocConfig), "RegisterDependencies")]

namespace ASPNETIdentityWithOnion.Bootstrapper
{
    public class IocConfig
    {
        public static void RegisterDependencies()
        {
            var builder = new ContainerBuilder();
            const string nameOrConnectionString = "name=AppContext";
            builder.RegisterControllers(typeof(MvcApplication).Assembly);
            builder.RegisterModule<AutofacWebTypesModule>();
            builder.RegisterGeneric(typeof(EntityRepository<>)).As(typeof(IRepository<>)).InstancePerHttpRequest();
            builder.RegisterGeneric(typeof(Service<>)).As(typeof(IService<>)).InstancePerHttpRequest();
            builder.RegisterType(typeof(UnitOfWork)).As(typeof(IUnitOfWork)).InstancePerHttpRequest();
            builder.Register<IEntitiesContext>(b =>
            {
                var logger = b.Resolve<ILogger>();
                var context = new AspnetIdentityWithOnionContext(nameOrConnectionString, logger);
                return context;
            }).InstancePerHttpRequest();
            builder.Register(b => NLogLogger.Instance).SingleInstance();
            builder.RegisterModule(new IdentityModule());

            var container = builder.Build();
            DependencyResolver.SetResolver(new AutofacDependencyResolver(container));
        }
    }
}
