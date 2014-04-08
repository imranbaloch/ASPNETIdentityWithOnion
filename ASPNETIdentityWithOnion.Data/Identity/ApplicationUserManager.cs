using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using ASPNETIdentityWithOnion.Core.DomainModels.Identity;
using ASPNETIdentityWithOnion.Data.Extensions;
using ASPNETIdentityWithOnion.Data.Identity.Models;
using Microsoft.AspNet.Identity;
using ASPNETIdentityWithOnion.Core.Identity;
using Microsoft.Owin.Security;

namespace ASPNETIdentityWithOnion.Data.Identity
{
    // Configure the application user manager used in this application. UserManager is defined in ASP.NET Identity and is used by the application.

    public class ApplicationUserManager : IApplicationUserManager
    {
        private readonly UserManager<ApplicationIdentityUser, int> _userManager;
        private readonly IAuthenticationManager _authenticationManager;
        private bool _disposed;
        public ApplicationUserManager(UserManager<ApplicationIdentityUser, int> userManager, IAuthenticationManager authenticationManager)
        {
            _userManager = userManager;
            _authenticationManager = authenticationManager;
        }

        public virtual string ApplicationCookie
        {
            get
            {
                return DefaultAuthenticationTypes.ApplicationCookie;
            }
        }

        public virtual string ExternalBearer
        {
            get
            {
                return DefaultAuthenticationTypes.ExternalBearer;
            }
        }

        public virtual string ExternalCookie
        {
            get
            {
                return DefaultAuthenticationTypes.ExternalCookie;
            }
        }

        public virtual string TwoFactorCookie
        {
            get
            {
                return DefaultAuthenticationTypes.TwoFactorCookie;
            }
        }

        public virtual string TwoFactorRememberBrowserCookie
        {
            get
            {
                return DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie;
            }
        }

        public virtual async Task<ApplicationIdentityResult> AccessFailedAsync(int userId)
        {
            var identityResult = await _userManager.AccessFailedAsync(userId).ConfigureAwait(false);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual async Task<ApplicationIdentityResult> AddClaimAsync(int userId, Claim claim)
        {
            var identityResult = await _userManager.AddClaimAsync(userId, claim).ConfigureAwait(false);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual async Task<ApplicationIdentityResult> AddLoginAsync(int userId, ApplicationUserLoginInfo login)
        {
            var identityResult = await _userManager.AddLoginAsync(userId, login.ToUserLoginInfo()).ConfigureAwait(false);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual async Task<ApplicationIdentityResult> AddPasswordAsync(int userId, string password)
        {
            var identityResult = await _userManager.AddPasswordAsync(userId, password).ConfigureAwait(false);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual async Task<ApplicationIdentityResult> AddToRoleAsync(int userId, string role)
        {
            var identityResult = await _userManager.AddToRoleAsync(userId, role).ConfigureAwait(false);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual ApplicationIdentityResult AddToRole(int userId, string role)
        {
            var identityResult = _userManager.AddToRole(userId, role);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual async Task<ApplicationIdentityResult> AddUserToRolesAsync(int userId, IList<string> roles)
        {
            var user = await FindByIdAsync(userId).ConfigureAwait(false);
            if (user == null)
            {
                throw new InvalidOperationException("Invalid user Id");
            }

            var userRoles = await GetRolesAsync(userId).ConfigureAwait(false);
            // Add user to each role using UserRoleStore
            foreach (var role in roles.Where(role => !userRoles.Contains(role)))
            {
                await AddToRoleAsync(userId, role).ConfigureAwait(false);
            }

            // Call update once when all roles are added
            return await UpdateAsync(userId).ConfigureAwait(false);
        }

        public virtual async Task<ApplicationIdentityResult> ChangePasswordAsync(int userId, string currentPassword, string newPassword)
        {
            var identityResult = await _userManager.ChangePasswordAsync(userId, currentPassword, newPassword).ConfigureAwait(false);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual async Task<ApplicationIdentityResult> ChangePhoneNumberAsync(int userId, string phoneNumber, string token)
        {
            var identityResult = await _userManager.ChangePhoneNumberAsync(userId, phoneNumber, token).ConfigureAwait(false);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual void Challenge(string redirectUri, string xsrfKey, int? userId, params string[] authenticationTypes)
        {
            var properties = new AuthenticationProperties { RedirectUri = redirectUri };
            if (userId != null)
            {
                properties.Dictionary[xsrfKey] = userId.ToString();
            }
            _authenticationManager.Challenge(properties, authenticationTypes);
        }

        public virtual async Task<bool> CheckPasswordAsync(AppUser user, string password)
        {
            var applicationUser = user.ToApplicationUser();
            var flag = await _userManager.CheckPasswordAsync(applicationUser, password).ConfigureAwait(false);
            user.CopyApplicationIdentityUserProperties(applicationUser);
            return flag;
        }

        public virtual async Task<ApplicationIdentityResult> ConfirmEmailAsync(int userId,  string token)
        {
            var identityResult = await _userManager.ConfirmEmailAsync(userId, token).ConfigureAwait(false);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual async Task<ApplicationIdentityResult> CreateAsync(AppUser user)
        {
            var applicationUser = user.ToApplicationUser();
            var identityResult = await _userManager.CreateAsync(applicationUser).ConfigureAwait(false);
            user.CopyApplicationIdentityUserProperties(applicationUser);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual async Task<ApplicationIdentityResult> CreateAsync(AppUser user, string password)
        {
            var applicationUser = user.ToApplicationUser();
            var identityResult = await _userManager.CreateAsync(applicationUser, password).ConfigureAwait(false);
            user.CopyApplicationIdentityUserProperties(applicationUser);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual ClaimsIdentity CreateIdentity(AppUser user, string authenticationType)
        {
            var applicationUser = user.ToApplicationUser();
            var claimsIdentity = _userManager.CreateIdentity(applicationUser, authenticationType);
            user.CopyApplicationIdentityUserProperties(applicationUser);
            return claimsIdentity;
        }

        public virtual async Task<ClaimsIdentity> CreateIdentityAsync(AppUser user, string authenticationType)
        {
            var applicationUser = user.ToApplicationUser();
            var claimsIdentity = await _userManager.CreateIdentityAsync(applicationUser, authenticationType).ConfigureAwait(false);
            user.CopyApplicationIdentityUserProperties(applicationUser);
            return claimsIdentity;
        }

        public virtual ApplicationIdentityResult Create(AppUser user)
        {
            var applicationUser = user.ToApplicationUser();
            var identityResult = _userManager.Create(applicationUser);
            user.CopyApplicationIdentityUserProperties(applicationUser);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual ApplicationIdentityResult Create(AppUser user, string password)
        {
            var applicationUser = user.ToApplicationUser();
            var identityResult = _userManager.Create(applicationUser, password);
            user.CopyApplicationIdentityUserProperties(applicationUser);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual ClaimsIdentity CreateTwoFactorRememberBrowserIdentity(int userId)
        {
            return _authenticationManager.CreateTwoFactorRememberBrowserIdentity(userId.ToString());
        }

        public virtual async Task<ApplicationIdentityResult> DeleteAsync(int userId)
        {
            var applicationUser = await _userManager.FindByIdAsync(userId);
            if (applicationUser == null)
            {
                return new ApplicationIdentityResult(new[] { "Invalid user Id" }, false);
            }
            var identityResult = await _userManager.DeleteAsync(applicationUser).ConfigureAwait(false);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual async Task<SignInStatus> ExternalSignIn(ApplicationExternalLoginInfo loginInfo, bool isPersistent)
        {
            var user = await FindAsync(loginInfo.Login).ConfigureAwait(false);
            if (user == null)
            {
                return SignInStatus.Failure;
            }
            if (await IsLockedOutAsync(user.Id).ConfigureAwait(false))
            {
                return SignInStatus.LockedOut;
            }
            return await SignInOrTwoFactor(user, isPersistent).ConfigureAwait(false);
        }

        public virtual async Task<AppUser> FindAsync(ApplicationUserLoginInfo login)
        {
            var user = await _userManager.FindAsync(login.ToUserLoginInfo()).ConfigureAwait(false);
            return user.ToAppUser();
        }

        public virtual async Task<AppUser> FindAsync(string userName, string password)
        {
            var user = await _userManager.FindAsync(userName, password).ConfigureAwait(false);
            return user.ToAppUser();
        }

        public virtual async Task<AppUser> FindByEmailAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email).ConfigureAwait(false);
            return user.ToAppUser();
        }

        public virtual AppUser FindById(int userId)
        {
            return _userManager.FindById(userId).ToAppUser();
        }

        public virtual async Task<AppUser> FindByIdAsync(int userId)
        {
            var user = await _userManager.FindByIdAsync(userId).ConfigureAwait(false);
            return user.ToAppUser();
        }

        public virtual async Task<AppUser> FindByNameAsync(string userName)
        {
            var user = await _userManager.FindByNameAsync(userName).ConfigureAwait(false);
            return user.ToAppUser();
        }

        public virtual AppUser FindByName(string userName)
        {
            var user = _userManager.FindByName(userName);
            return user.ToAppUser();
        }

        public virtual async Task<string> GenerateChangePhoneNumberTokenAsync(int userId, string phoneNumber)
        {
             return await _userManager.GenerateChangePhoneNumberTokenAsync(userId, phoneNumber).ConfigureAwait(false);
        }

        public virtual async Task<string> GenerateEmailConfirmationTokenAsync(int userId)
        {
            return await _userManager.GenerateEmailConfirmationTokenAsync(userId).ConfigureAwait(false);
        }

        public virtual async Task<string> GeneratePasswordResetTokenAsync(int userId)
        {
            return await _userManager.GeneratePasswordResetTokenAsync(userId).ConfigureAwait(false);
        }

        public virtual async Task<string> GenerateTwoFactorTokenAsync(int userId, string twoFactorProvider)
        {
            return await _userManager.GenerateTwoFactorTokenAsync(userId, twoFactorProvider).ConfigureAwait(false);
        }

        public virtual async Task<string> GenerateUserTokenAsync(string purpose, int userId)
        {
            return await _userManager.GenerateUserTokenAsync(purpose, userId).ConfigureAwait(false);
        }

        public virtual async Task<int> GetAccessFailedCountAsync(int userId)
        {
            return await _userManager.GetAccessFailedCountAsync(userId).ConfigureAwait(false);
        }

        public virtual async Task<IList<Claim>> GetClaimsAsync(int userId)
        {
            return await _userManager.GetClaimsAsync(userId).ConfigureAwait(false);
        }

        public virtual async Task<string> GetEmailAsync(int userId)
        {
            return await _userManager.GetEmailAsync(userId).ConfigureAwait(false);
        }

        public virtual IEnumerable<ApplicationAuthenticationDescription> GetExternalAuthenticationTypes()
        {
            return _authenticationManager.GetExternalAuthenticationTypes().ToApplicationAuthenticationDescriptionList();
        }

        public virtual async Task<ClaimsIdentity> GetExternalIdentityAsync(string externalAuthenticationType)
        {
            return await _authenticationManager.GetExternalIdentityAsync(externalAuthenticationType).ConfigureAwait(false);
        }

        public virtual ApplicationExternalLoginInfo GetExternalLoginInfo()
        {
            return _authenticationManager.GetExternalLoginInfo().ToApplicationExternalLoginInfo();
        }

        public virtual ApplicationExternalLoginInfo GetExternalLoginInfo(string xsrfKey, string expectedValue)
        {
            return _authenticationManager.GetExternalLoginInfo(xsrfKey, expectedValue).ToApplicationExternalLoginInfo();
        }

        public virtual async Task<ApplicationExternalLoginInfo> GetExternalLoginInfoAsync()
        {
            var externalLoginInfo = await _authenticationManager.GetExternalLoginInfoAsync().ConfigureAwait(false);
            return externalLoginInfo.ToApplicationExternalLoginInfo();
        }

        public virtual async Task<ApplicationExternalLoginInfo> GetExternalLoginInfoAsync(string xsrfKey, string expectedValue)
        {
            var externalLoginInfo = await _authenticationManager.GetExternalLoginInfoAsync(xsrfKey, expectedValue).ConfigureAwait(false);
            return externalLoginInfo.ToApplicationExternalLoginInfo();
        }

        public virtual async Task<bool> GetLockoutEnabledAsync(int userId)
        {
            return await _userManager.GetLockoutEnabledAsync(userId).ConfigureAwait(false);
        }

        public virtual async Task<DateTimeOffset> GetLockoutEndDateAsync(int userId)
        {
            return await _userManager.GetLockoutEndDateAsync(userId).ConfigureAwait(false);
        }

        public virtual IList<ApplicationUserLoginInfo> GetLogins(int userId)
        {
            return _userManager.GetLogins(userId).ToApplicationUserLoginInfoList();
        }

        public virtual async Task<IList<ApplicationUserLoginInfo>> GetLoginsAsync(int userId)
        {
            var list = await _userManager.GetLoginsAsync(userId).ConfigureAwait(false);
            return list.ToApplicationUserLoginInfoList();
        }

        public virtual async Task<string> GetPhoneNumberAsync(int userId)
        {
            return await _userManager.GetPhoneNumberAsync(userId).ConfigureAwait(false);
        }

        public virtual IList<string> GetRoles(int userId)
        {
            return _userManager.GetRoles(userId);
        }

        public virtual async Task<IList<string>> GetRolesAsync(int userId)
        {
             return await _userManager.GetRolesAsync(userId).ConfigureAwait(false);
        }

        public virtual async Task<string> GetSecurityStampAsync(int userId)
        {
            return await _userManager.GetSecurityStampAsync(userId).ConfigureAwait(false);
        }

        public virtual async Task<bool> GetTwoFactorEnabledAsync(int userId)
        {
            return await _userManager.GetTwoFactorEnabledAsync(userId).ConfigureAwait(false);
        }

        public virtual async Task<IList<string>> GetValidTwoFactorProvidersAsync(int userId)
        {
            return await _userManager.GetValidTwoFactorProvidersAsync(userId).ConfigureAwait(false);
        }

        public virtual async Task<int?> GetVerifiedUserIdAsync()
        {
            var result = await _authenticationManager.AuthenticateAsync(DefaultAuthenticationTypes.TwoFactorCookie).ConfigureAwait(false);
            if (result != null && result.Identity != null && !String.IsNullOrEmpty(result.Identity.GetUserId()))
            {
                return int.Parse(result.Identity.GetUserId());
            }
            return null;
        }

        public virtual async Task<bool> HasBeenVerified()
        {
            return await GetVerifiedUserIdAsync().ConfigureAwait(false) != null;
        }

        public virtual async Task<bool> HasPasswordAsync(int userId)
        {
            return await _userManager.HasPasswordAsync(userId).ConfigureAwait(false);
        }

        public virtual async Task<bool> IsEmailConfirmedAsync(int userId)
        {
            return await _userManager.IsEmailConfirmedAsync(userId).ConfigureAwait(false);
        }

        public virtual async Task<bool> IsInRoleAsync(int userId, string role)
        {
            return await _userManager.IsInRoleAsync(userId,role).ConfigureAwait(false);
        }

        public virtual async Task<bool> IsLockedOutAsync(int userId)
        {
            return await _userManager.IsLockedOutAsync(userId).ConfigureAwait(false);
        }

        public virtual async Task<bool> IsPhoneNumberConfirmedAsync(int userId)
        {
            return await _userManager.IsPhoneNumberConfirmedAsync(userId).ConfigureAwait(false);
        }

        public virtual async Task<ApplicationIdentityResult> NotifyTwoFactorTokenAsync(int userId, string twoFactorProvider, string token)
        {
            var identityResult = await _userManager.NotifyTwoFactorTokenAsync(userId, twoFactorProvider, token).ConfigureAwait(false);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual async Task<SignInStatus> PasswordSignIn(string userName, string password, bool isPersistent, bool shouldLockout)
        {
            var user = await FindByNameAsync(userName).ConfigureAwait(false);
            if (user == null)
            {
                return SignInStatus.Failure;
            }
            if (await IsLockedOutAsync(user.Id).ConfigureAwait(false))
            {
                return SignInStatus.LockedOut;
            }
            if (await CheckPasswordAsync(user, password).ConfigureAwait(false))
            {
                return await SignInOrTwoFactor(user, isPersistent).ConfigureAwait(false);
            }
            if (shouldLockout)
            {
                // If lockout is requested, increment access failed count which might lock out the user
                await AccessFailedAsync(user.Id).ConfigureAwait(false);
                if (await IsLockedOutAsync(user.Id).ConfigureAwait(false))
                {
                    return SignInStatus.LockedOut;
                }
            }
            return SignInStatus.Failure;
        }

        public virtual async Task<ApplicationIdentityResult> RemoveClaimAsync(int userId, Claim claim)
        {
            var identityResult = await _userManager.RemoveClaimAsync(userId, claim).ConfigureAwait(false);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual async Task<ApplicationIdentityResult> RemoveFromRoleAsync(int userId, string role)
        {
            var identityResult = await _userManager.RemoveFromRoleAsync(userId, role).ConfigureAwait(false);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual async Task<ApplicationIdentityResult> RemoveLoginAsync(int userId,
            ApplicationUserLoginInfo login)
        {
            var identityResult = await _userManager.RemoveLoginAsync(userId, login.ToUserLoginInfo()).ConfigureAwait(false);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual async Task<ApplicationIdentityResult> RemovePasswordAsync(int userId)
        {
            var identityResult = await _userManager.RemovePasswordAsync(userId).ConfigureAwait(false);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual async Task<ApplicationIdentityResult> RemoveUserFromRolesAsync(int userId, IList<string> roles)
        {
            var user = await FindByIdAsync(userId).ConfigureAwait(false);
            if (user == null)
            {
                throw new InvalidOperationException("Invalid user Id");
            }

            var userRoles = await GetRolesAsync(user.Id).ConfigureAwait(false);
            // Remove user to each role using UserRoleStore
            foreach (var role in roles.Where(userRoles.Contains))
            {
                await RemoveFromRoleAsync(user.Id, role).ConfigureAwait(false);
            }

            // Call update once when all roles are removed
            return await UpdateAsync(user.Id).ConfigureAwait(false);
        }

        public virtual async Task<ApplicationIdentityResult> ResetAccessFailedCountAsync(int userId)
        {
            var identityResult = await _userManager.ResetAccessFailedCountAsync(userId).ConfigureAwait(false);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual async Task<ApplicationIdentityResult> ResetPasswordAsync(int userId, string token,
            string newPassword)
        {
            var identityResult = await _userManager.ResetPasswordAsync(userId, token, newPassword).ConfigureAwait(false);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual async Task SendEmailAsync(int userId, string subject, string body)
        {
            await _userManager.SendEmailAsync(userId, subject, body).ConfigureAwait(false);
        }

        public virtual async Task SendSmsAsync(int userId, string message)
        {
            await _userManager.SendSmsAsync(userId, message).ConfigureAwait(false);
        }

        public virtual async Task SendSmsAsync(ApplicationMessage message)
        {
            if (_userManager.SmsService != null)
            {
                await _userManager.SmsService.SendAsync(message.ToIdentityMessage());
            }
        }

        public virtual async Task<bool> SendTwoFactorCode(string provider)
        {
            var userId = await GetVerifiedUserIdAsync().ConfigureAwait(false);
            if (userId == null)
            {
                return false;
            }

            var token = await GenerateTwoFactorTokenAsync(userId.Value, provider).ConfigureAwait(false);
            await NotifyTwoFactorTokenAsync(userId.Value, provider, token).ConfigureAwait(false);
            return true;
        }

        public virtual async Task<ApplicationIdentityResult> SetEmailAsync(int userId, string email)
        {
            var identityResult = await _userManager.SetEmailAsync(userId, email).ConfigureAwait(false);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual ApplicationIdentityResult SetLockoutEnabled(int userId, bool enabled)
        {
            var identityResult = _userManager.SetLockoutEnabled(userId, enabled);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual async Task<ApplicationIdentityResult> SetLockoutEnabledAsync(int userId, bool enabled)
        {
            var identityResult = await _userManager.SetLockoutEnabledAsync(userId, enabled).ConfigureAwait(false);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual async Task<ApplicationIdentityResult> SetLockoutEndDateAsync(int userId,
            DateTimeOffset lockoutEnd)
        {
            var identityResult = await _userManager.SetLockoutEndDateAsync(userId, lockoutEnd).ConfigureAwait(false);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual async Task<ApplicationIdentityResult> SetPhoneNumberAsync(int userId, string phoneNumber)
        {
            var identityResult = await _userManager.SetPhoneNumberAsync(userId, phoneNumber).ConfigureAwait(false);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual async Task<ApplicationIdentityResult> SetTwoFactorEnabledAsync(int userId, bool enabled)
        {
            var identityResult = await _userManager.SetTwoFactorEnabledAsync(userId, enabled).ConfigureAwait(false);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual async Task<SignInStatus> SignInOrTwoFactor(AppUser user, bool isPersistent)
        {
            if (await GetTwoFactorEnabledAsync(user.Id).ConfigureAwait(false) &&
                !await TwoFactorBrowserRememberedAsync(user.Id).ConfigureAwait(false))
            {
                var identity = new ClaimsIdentity(DefaultAuthenticationTypes.TwoFactorCookie);
                identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
                SignIn(identity);
                return SignInStatus.RequiresTwoFactorAuthentication;
            }
            await SignInAsync(user, isPersistent, false).ConfigureAwait(false);
            return SignInStatus.Success;

        }

        public virtual void SignIn(params ClaimsIdentity[] identities)
        {
            _authenticationManager.SignIn(identities);
        }

        public virtual void SignIn(bool isPersistent, params ClaimsIdentity[] identities)
        {
            _authenticationManager.SignIn(new AuthenticationProperties { IsPersistent = isPersistent }, identities);
        }

        public virtual void SignIn(AppUser user, bool isPersistent, bool rememberBrowser)
        {
            // Clear any partial cookies from external or two factor partial sign ins
            SignOut(DefaultAuthenticationTypes.ExternalCookie, DefaultAuthenticationTypes.TwoFactorCookie);
            var userIdentity = CreateIdentity(user, DefaultAuthenticationTypes.ApplicationCookie);
            if (rememberBrowser)
            {
                var rememberBrowserIdentity = CreateTwoFactorRememberBrowserIdentity(user.Id);
                _authenticationManager.SignIn(new AuthenticationProperties { IsPersistent = isPersistent }, userIdentity, rememberBrowserIdentity);
            }
            else
            {
                _authenticationManager.SignIn(new AuthenticationProperties { IsPersistent = isPersistent }, userIdentity);
            }
        }

        public virtual async Task SignInAsync(AppUser user, bool isPersistent, bool rememberBrowser)
        {
            // Clear any partial cookies from external or two factor partial sign ins
            SignOut(DefaultAuthenticationTypes.ExternalCookie, DefaultAuthenticationTypes.TwoFactorCookie);
            var userIdentity = await CreateIdentityAsync(user, DefaultAuthenticationTypes.ApplicationCookie).ConfigureAwait(false);
            if (rememberBrowser)
            {
                var rememberBrowserIdentity = CreateTwoFactorRememberBrowserIdentity(user.Id);
                _authenticationManager.SignIn(new AuthenticationProperties { IsPersistent = isPersistent }, userIdentity, rememberBrowserIdentity);
            }
            else
            {
                _authenticationManager.SignIn(new AuthenticationProperties { IsPersistent = isPersistent }, userIdentity);
            }
        }

        public void SignOut(params string[] authenticationTypes)
        {
            _authenticationManager.SignOut(authenticationTypes);
        }

        public virtual async Task<bool> TwoFactorBrowserRememberedAsync(int userId)
        {
            return await _authenticationManager.TwoFactorBrowserRememberedAsync(userId.ToString()).ConfigureAwait(false);
        }

        public virtual async Task<SignInStatus> TwoFactorSignIn(string provider, string code, bool isPersistent, bool rememberBrowser)
        {
            var userId = await GetVerifiedUserIdAsync().ConfigureAwait(false);
            if (userId == null)
            {
                return SignInStatus.Failure;
            }
            var user = await FindByIdAsync(userId.Value).ConfigureAwait(false);
            if (user == null)
            {
                return SignInStatus.Failure;
            }
            if (await IsLockedOutAsync(user.Id).ConfigureAwait(false))
            {
                return SignInStatus.LockedOut;
            }
            if (await VerifyTwoFactorTokenAsync(user.Id, provider, code).ConfigureAwait(false))
            {
                // When token is verified correctly, clear the access failed count used for lockout
                await ResetAccessFailedCountAsync(user.Id).ConfigureAwait(false);
                await SignInAsync(user, isPersistent, rememberBrowser).ConfigureAwait(false);
                return SignInStatus.Success;
            }
            // If the token is incorrect, record the failure which also may cause the user to be locked out
            await AccessFailedAsync(user.Id).ConfigureAwait(false);
            return SignInStatus.Failure;
        }

        public virtual async Task<ApplicationIdentityResult> UpdateAsync(int userId)
        {
            var applicationUser = await _userManager.FindByIdAsync(userId).ConfigureAwait(false);
            if (applicationUser == null)
            {
                return new ApplicationIdentityResult(new[] { "Invalid user Id" }, false);
            }
            var identityResult = await _userManager.UpdateAsync(applicationUser).ConfigureAwait(false);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual async Task<ApplicationIdentityResult> UpdateSecurityStampAsync(int userId)
        {
            var identityResult = await _userManager.UpdateSecurityStampAsync(userId).ConfigureAwait(false);
            return identityResult.ToApplicationIdentityResult();
        }

        public virtual IEnumerable<AppUser> GetUsers()
        {
            return _userManager.Users.ToList().ToAppUserList();
        }

        public virtual async Task<IEnumerable<AppUser>> GetUsersAsync()
        {
            var users = await _userManager.Users.ToListAsync().ConfigureAwait(false);
            return users.ToAppUserList();
        }

        public virtual async Task<bool> VerifyChangePhoneNumberTokenAsync(int userId, string token,
            string phoneNumber)
        {
            return await _userManager.VerifyChangePhoneNumberTokenAsync(userId, token, phoneNumber).ConfigureAwait(false);
        }

        public virtual async Task<bool> VerifyTwoFactorTokenAsync(int userId, string twoFactorProvider, string token)
        {
            return await _userManager.VerifyTwoFactorTokenAsync(userId, twoFactorProvider, token).ConfigureAwait(false);
        }

        public virtual async Task<bool> VerifyUserTokenAsync(int userId, string purpose, string token)
        {
            return await _userManager.VerifyUserTokenAsync(userId, purpose, token).ConfigureAwait(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public virtual void Dispose(bool disposing)
        {
            if (!_disposed && disposing)
            {
                if (_userManager != null)
                {
                    _userManager.Dispose();
                }
            }
            _disposed = true;
        }
    }
}
