namespace ASPNETIdentityWithOnion.Core.DomainModels.Identity
{
    public sealed class ApplicationUserLoginInfo
    {
        public string LoginProvider
        {
            get;
            set;
        }

        public string ProviderKey
        {
            get;
            set;
        }

        public ApplicationUserLoginInfo(string loginProvider, string providerKey)
        {
            LoginProvider = loginProvider;
            ProviderKey = providerKey;
        }
    }
}
