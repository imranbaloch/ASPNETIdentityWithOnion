using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using ASPNETIdentityWithOnion.Core.DomainModels.Identity;
using ASPNETIdentityWithOnion.Data.Identity.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;

namespace ASPNETIdentityWithOnion.Data.Extensions
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static class IdentityExtensions
    {
        public static ApplicationIdentityResult ToApplicationIdentityResult(this IdentityResult identityResult)
        {
            return identityResult == null ? null : new ApplicationIdentityResult(identityResult.Errors, identityResult.Succeeded);
        }

        public static ApplicationIdentityUser ToApplicationUser(this AppUser appUser)
        {
            if (appUser == null)
            {
                return null;
            }
            var applicationUser = new ApplicationIdentityUser();
            return applicationUser.CopyAppUserProperties(appUser);
        }

        public static ApplicationIdentityUser CopyAppUserProperties(this ApplicationIdentityUser applicationIdentityUser, AppUser appUser)
        {
            if (appUser == null)
            {
                return null;
            }
            if (applicationIdentityUser == null)
            {
                return null;
            }
            applicationIdentityUser.UserName = appUser.UserName;
            applicationIdentityUser.Id = appUser.Id;
            applicationIdentityUser.AccessFailedCount = appUser.AccessFailedCount;
            applicationIdentityUser.Email = appUser.Email;
            applicationIdentityUser.EmailConfirmed = appUser.EmailConfirmed;
            applicationIdentityUser.LockoutEnabled = appUser.LockoutEnabled;
            applicationIdentityUser.LockoutEndDateUtc = appUser.LockoutEndDateUtc;
            applicationIdentityUser.PasswordHash = appUser.PasswordHash;
            applicationIdentityUser.PhoneNumber = appUser.PhoneNumber;
            applicationIdentityUser.PhoneNumberConfirmed = appUser.PhoneNumberConfirmed;
            applicationIdentityUser.SecurityStamp = appUser.SecurityStamp;
            applicationIdentityUser.TwoFactorEnabled = appUser.TwoFactorEnabled;
            foreach (var claim in appUser.Claims)
            {
                applicationIdentityUser.Claims.Add(new ApplicationIdentityUserClaim
                {
                    ClaimType = claim.ClaimType,
                    ClaimValue = claim.ClaimValue,
                    Id = claim.Id,
                    UserId = claim.UserId
                });
            }
            foreach (var role in appUser.Roles)
            {
                applicationIdentityUser.Roles.Add(role.ToIdentityUserRole());
            }
            foreach (var login in appUser.Logins)
            {
                applicationIdentityUser.Logins.Add(new ApplicationIdentityUserLogin
                {
                    LoginProvider = login.LoginProvider,
                    ProviderKey = login.ProviderKey,
                    UserId = login.UserId
                });
            }
            return applicationIdentityUser;
        }

        public static AppUser ToAppUser(this ApplicationIdentityUser applicationIdentityUser)
        {
            if (applicationIdentityUser == null)
            {
                return null;
            }
            var appUser = new AppUser();
            return appUser.CopyApplicationIdentityUserProperties(applicationIdentityUser);
        }

        public static AppUser CopyApplicationIdentityUserProperties(this AppUser appUser, ApplicationIdentityUser applicationIdentityUser)
        {
            if (appUser == null)
            {
                return null;
            }
            if (applicationIdentityUser == null)
            {
                return null;
            }
            appUser.UserName = applicationIdentityUser.UserName;
            appUser.Id = applicationIdentityUser.Id;
            appUser.AccessFailedCount = applicationIdentityUser.AccessFailedCount;
            appUser.Email = applicationIdentityUser.Email;
            appUser.EmailConfirmed = applicationIdentityUser.EmailConfirmed;
            appUser.LockoutEnabled = applicationIdentityUser.LockoutEnabled;
            appUser.LockoutEndDateUtc = applicationIdentityUser.LockoutEndDateUtc;
            appUser.PasswordHash = applicationIdentityUser.PasswordHash;
            appUser.PhoneNumber = applicationIdentityUser.PhoneNumber;
            appUser.PhoneNumberConfirmed = applicationIdentityUser.PhoneNumberConfirmed;
            appUser.SecurityStamp = applicationIdentityUser.SecurityStamp;
            appUser.TwoFactorEnabled = applicationIdentityUser.TwoFactorEnabled;
            foreach (var claim in applicationIdentityUser.Claims)
            {
                appUser.Claims.Add(new ApplicationUserClaim
                {
                    ClaimType = claim.ClaimType,
                    ClaimValue = claim.ClaimValue,
                    Id = claim.Id,
                    UserId = claim.UserId
                });
            }
            foreach (var role in applicationIdentityUser.Roles)
            {
                appUser.Roles.Add(role.ToApplicationUserRole());
            }
            foreach (var login in applicationIdentityUser.Logins)
            {
                appUser.Logins.Add(new ApplicationUserLogin
                {
                    LoginProvider = login.LoginProvider,
                    ProviderKey = login.ProviderKey,
                    UserId = login.UserId
                });
            }
            return appUser;
        }

        public static ApplicationUserRole ToApplicationUserRole(this IdentityUserRole<int> role)
        {
            return role == null ? null : new ApplicationUserRole { RoleId = role.RoleId, UserId = role.UserId };
        }

        public static ApplicationIdentityUserRole ToIdentityUserRole(this ApplicationUserRole role)
        {
            return role == null ? null : new ApplicationIdentityUserRole { RoleId = role.RoleId, UserId = role.UserId };
        }

        public static ApplicationExternalLoginInfo ToApplicationExternalLoginInfo(this ExternalLoginInfo externalLoginInfo)
        {
            return externalLoginInfo == null ? null : new ApplicationExternalLoginInfo { DefaultUserName = externalLoginInfo.DefaultUserName, Email = externalLoginInfo.Email, ExternalIdentity = externalLoginInfo.ExternalIdentity, Login = externalLoginInfo.Login.ToApplicationUserLoginInfo() };
        }

        public static ExternalLoginInfo ToExternalLoginInfo(this ApplicationExternalLoginInfo externalLoginInfo)
        {
            return externalLoginInfo == null ? null : new ExternalLoginInfo { DefaultUserName = externalLoginInfo.DefaultUserName, Email = externalLoginInfo.Email, ExternalIdentity = externalLoginInfo.ExternalIdentity, Login = externalLoginInfo.Login.ToUserLoginInfo() };
        }

        public static ApplicationAuthenticationDescription ToApplicationAuthenticationDescription(this AuthenticationDescription authenticationDescription)
        {
            if (authenticationDescription == null)
            {
                return null;
            }
            var description = new ApplicationAuthenticationDescription { AuthenticationType = authenticationDescription.AuthenticationType, Caption = authenticationDescription.Caption };
            description.Properties.Clear();
            foreach (var property in authenticationDescription.Properties)
            {
                description.Properties.Add(property.Key, property.Value);
            }
            return description;
        }

        public static AuthenticationDescription ToAuthenticationDescription(this ApplicationAuthenticationDescription authenticationDescription)
        {
            if (authenticationDescription == null)
            {
                return null;
            }
            var description = new AuthenticationDescription { AuthenticationType = authenticationDescription.AuthenticationType, Caption = authenticationDescription.Caption };
            description.Properties.Clear();
            foreach (var property in authenticationDescription.Properties)
            {
                description.Properties.Add(property.Key, property.Value);
            }
            return description;
        }

        public static ApplicationRole ToApplicationRole(this ApplicationIdentityRole identityRole)
        {
            if (identityRole == null)
            {
                return null;
            }
            var applicationRole = new ApplicationRole();
            return applicationRole.CopyIdentityRoleProperties(identityRole);
        }

        public static ApplicationRole CopyIdentityRoleProperties(this ApplicationRole applicationRole, ApplicationIdentityRole identityRole)
        {
            if (identityRole == null)
            {
                return null;
            }
            if (applicationRole == null)
            {
                return null;
            }
            applicationRole.Name = identityRole.Name;
            applicationRole.Id = identityRole.Id;
            foreach (var userRole in identityRole.Users)
            {
                applicationRole.Users.Add(userRole.ToApplicationUserRole());
            }
            return applicationRole;
        }

        public static ApplicationIdentityRole ToIdentityRole(this ApplicationRole applicationRole)
        {
            if (applicationRole == null)
            {
                return null;
            }
            var identityRole = new ApplicationIdentityRole();
            return identityRole.CopyApplicationRoleProperties(applicationRole);
        }

        public static ApplicationIdentityRole CopyApplicationRoleProperties(this ApplicationIdentityRole identityRole, ApplicationRole applicationRole)
        {
            if (identityRole == null)
            {
                return null;
            }
            if (applicationRole == null)
            {
                return null;
            }
            identityRole.Name = applicationRole.Name;
            identityRole.Id = applicationRole.Id;
            foreach (var userRole in applicationRole.Users)
            {
                identityRole.Users.Add(userRole.ToIdentityUserRole());
            }
            return identityRole;
        }

        public static UserLoginInfo ToUserLoginInfo(this ApplicationUserLoginInfo loginInfo)
        {
            return loginInfo == null ? null : new UserLoginInfo(loginInfo.LoginProvider, loginInfo.ProviderKey);
        }

        public static ApplicationUserLoginInfo ToApplicationUserLoginInfo(this UserLoginInfo loginInfo)
        {
            return loginInfo == null ? null : new ApplicationUserLoginInfo(loginInfo.LoginProvider, loginInfo.ProviderKey);
        }

        public static ApplicationMessage ToApplicationMessage(this IdentityMessage message)
        {
            return message == null ? null : new ApplicationMessage { Body = message.Body, Destination = message.Destination, Subject = message.Subject };
        }

        public static IdentityMessage ToIdentityMessage(this ApplicationMessage message)
        {
            return message == null ? null : new IdentityMessage { Body = message.Body, Destination = message.Destination, Subject = message.Subject };
        }

        public static IList<UserLoginInfo> ToUserLoginInfoList(this IList<ApplicationUserLoginInfo> list)
        {
            return list.Select(u => u.ToUserLoginInfo()).ToList();
        }

        public static IList<ApplicationUserLoginInfo> ToApplicationUserLoginInfoList(this IList<UserLoginInfo> list)
        {
            return list.Select(u => u.ToApplicationUserLoginInfo()).ToList();
        }

        public static IEnumerable<ApplicationAuthenticationDescription> ToApplicationAuthenticationDescriptionList(this IEnumerable<AuthenticationDescription> list)
        {
            return list.Select(u => u.ToApplicationAuthenticationDescription()).ToList();
        }

        public static IEnumerable<AuthenticationDescription> ToAuthenticationDescriptionList(this IList<ApplicationAuthenticationDescription> list)
        {
            return list.Select(u => u.ToAuthenticationDescription()).ToList();
        }

        public static IEnumerable<ApplicationUserRole> ToApplicationUserRoleList(this IEnumerable<IdentityUserRole<int>> list)
        {
            return list.Select(u => u.ToApplicationUserRole()).ToList();
        }

        public static IEnumerable<IdentityUserRole<int>> ToIdentityUserRoleList(this IEnumerable<ApplicationUserRole> list)
        {
            return list.Select(u => u.ToIdentityUserRole()).ToList();
        }

        public static IEnumerable<ApplicationRole> ToApplicationRoleList(this IEnumerable<ApplicationIdentityRole> list)
        {
            return list.Select(u => u.ToApplicationRole()).ToList();
        }

        public static IEnumerable<ApplicationIdentityRole> ToIdentityRoleList(this IEnumerable<ApplicationRole> list)
        {
            return list.Select(u => u.ToIdentityRole()).ToList();
        }

        public static IEnumerable<ApplicationIdentityUser> ToApplicationUserList(this IEnumerable<AppUser> list)
        {
            return list.Select(u => u.ToApplicationUser()).ToList();
        }

        public static IEnumerable<AppUser> ToAppUserList(this IEnumerable<ApplicationIdentityUser> list)
        {
            return list.Select(u => u.ToAppUser()).ToList();
        }
    }
}
