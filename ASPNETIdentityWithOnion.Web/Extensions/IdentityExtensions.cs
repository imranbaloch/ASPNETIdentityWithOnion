using System;
using System.Security.Claims;
using System.Security.Principal;

namespace ASPNETIdentityWithOnion.Web.Extensions
{
    public static class IdentityExtensions
    {
        public static string FindFirstValue(this ClaimsIdentity identity, string claimType)
        {
            if (identity == null)
            {
                throw new ArgumentNullException("identity");
            }
            var claim = identity.FindFirst(claimType);
            return claim == null ? null : claim.Value;
        }

        public static int? GetUserId(this IIdentity identity)
        {
            if (identity == null)
            {
                throw new ArgumentNullException("identity");
            }
            var claimsIdentity = identity as ClaimsIdentity;
            return claimsIdentity == null ? (int?)null : int.Parse(claimsIdentity.FindFirstValue("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"));
        }

        public static string GetUserName(this IIdentity identity)
        {
            if (identity == null)
            {
                throw new ArgumentNullException("identity");
            }
            var claimsIdentity = identity as ClaimsIdentity;
            return claimsIdentity == null ? null : claimsIdentity.FindFirstValue("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name");
        }
    }
}