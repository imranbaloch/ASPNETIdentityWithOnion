using System.Collections.Generic;

namespace ASPNETIdentityWithOnion.Core.DomainModels.Identity
{
    public class ApplicationIdentityResult
    {
        public IEnumerable<string> Errors
        {
            get;
            private set;
        }

        public bool Succeeded
        {
            get;
            private set;
        }

        public ApplicationIdentityResult(IEnumerable<string> errors, bool succeeded)
        {
            Succeeded = succeeded;
            Errors = errors;
        }
    }
}
