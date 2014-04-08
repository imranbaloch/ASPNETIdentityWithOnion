using ASPNETIdentityWithOnion.Core.DomainModels.Identity;
using ASPNETIdentityWithOnion.Core.Identity;
using ASPNETIdentityWithOnion.Web.Models;
using ASPNETIdentityWithOnion.Web.Extensions;
using System.Linq;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace ASPNETIdentityWithOnion.Web.Controllers
{
    [Authorize]
    public class ManageController : Controller
    {
        private IApplicationUserManager _userManager;
        public ManageController(IApplicationUserManager userManager)
        {
            _userManager = userManager;
        }

        public int UserId
        {
            get
            {
                var userId = User.Identity.GetUserId();
                return userId != null ? userId.Value : 0;
            }
        }

        //
        // GET: /Account/Index
        public async Task<ActionResult> Index(ManageMessageId? message)
        {
            ViewBag.StatusMessage =
                message == ManageMessageId.ChangePasswordSuccess ? "Your password has been changed."
                : message == ManageMessageId.SetPasswordSuccess ? "Your password has been set."
                : message == ManageMessageId.SetTwoFactorSuccess ? "Your two factor provider has been set."
                : message == ManageMessageId.Error ? "An error has occurred."
                : message == ManageMessageId.AddPhoneSuccess ? "The phone number was added."
                : message == ManageMessageId.RemovePhoneSuccess ? "Your phone number was removed."
                : "";

            var model = new IndexViewModel
            {
                HasPassword = HasPassword(),
                PhoneNumber = await _userManager.GetPhoneNumberAsync(UserId),
                TwoFactor = await _userManager.GetTwoFactorEnabledAsync(UserId),
                Logins = await _userManager.GetLoginsAsync(UserId),
                BrowserRemembered = await _userManager.TwoFactorBrowserRememberedAsync(UserId)
            };
            return View(model);
        }

        //
        // GET: /Account/RemoveLogin
        public ActionResult RemoveLogin()
        {
            var linkedAccounts = _userManager.GetLogins(UserId);
            ViewBag.ShowRemoveButton = HasPassword() || linkedAccounts.Count > 1;
            return View(linkedAccounts);
        }

        //
        // POST: /Manage/RemoveLogin
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> RemoveLogin(string loginProvider, string providerKey)
        {
            ManageMessageId? message;
            var result = await _userManager.RemoveLoginAsync(UserId, new ApplicationUserLoginInfo(loginProvider, providerKey));
            if (result.Succeeded)
            {
                var user = await _userManager.FindByIdAsync(UserId);
                if (user != null)
                {
                    await SignInAsync(user, isPersistent: false);
                }
                message = ManageMessageId.RemoveLoginSuccess;
            }
            else
            {
                message = ManageMessageId.Error;
            }
            return RedirectToAction("ManageLogins", new { Message = message });
        }

        //
        // GET: /Account/AddPhoneNumber
        public ActionResult AddPhoneNumber()
        {
            return View();
        }

        //
        // GET: /Manage/RememberBrowser
        public ActionResult RememberBrowser()
        {
            var rememberBrowserIdentity = _userManager.CreateTwoFactorRememberBrowserIdentity(UserId);
            _userManager.SignIn(true, rememberBrowserIdentity);
            return RedirectToAction("Index", "Manage");
        }

        //
        // GET: /Manage/ForgetBrowser
        public ActionResult ForgetBrowser()
        {
            _userManager.SignOut(_userManager.TwoFactorRememberBrowserCookie);
            return RedirectToAction("Index", "Manage");
        }

        //
        // GET: /Manage/EnableTFA
        public async Task<ActionResult> EnableTFA()
        {
            await _userManager.SetTwoFactorEnabledAsync(UserId, true);
            var user = await _userManager.FindByIdAsync(UserId);
            if (user != null)
            {
                await SignInAsync(user, isPersistent: false);
            }
            return RedirectToAction("Index", "Manage");
        }

        //
        // GET: /Manage/DisableTFA
        public async Task<ActionResult> DisableTFA()
        {
            await _userManager.SetTwoFactorEnabledAsync(UserId, false);
            var user = await _userManager.FindByIdAsync(UserId);
            if (user != null)
            {
                await SignInAsync(user, isPersistent: false);
            }
            return RedirectToAction("Index", "Manage");
        }

        //
        // POST: /Account/AddPhoneNumber
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> AddPhoneNumber(AddPhoneNumberViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            // Send result of: _userManager.GetPhoneNumberCodeAsync(UserId, phoneNumber);
            // Generate the token and send it
            var code = await _userManager.GenerateChangePhoneNumberTokenAsync(UserId, model.Number);
            var message = new ApplicationMessage
            {
                Destination = model.Number,
                Body = "Your security code is: " + code
            };
            await _userManager.SendSmsAsync(message);
            return RedirectToAction("VerifyPhoneNumber", new { PhoneNumber = model.Number });
        }

        //
        // GET: /Account/VerifyPhoneNumber
        public async Task<ActionResult> VerifyPhoneNumber(string phoneNumber)
        {
            // This code allows you exercise the flow without actually sending codes
            // For production use please register a SMS provider in IdentityConfig and generate a code here.
            var code = await _userManager.GenerateChangePhoneNumberTokenAsync(UserId, phoneNumber);
            ViewBag.Status = "For DEMO purposes only, the current code is " + code ;
            return phoneNumber == null ? View("Error") : View(new VerifyPhoneNumberViewModel { PhoneNumber = phoneNumber });
        }

        //
        // POST: /Account/VerifyPhoneNumber
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyPhoneNumber(VerifyPhoneNumberViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var result = await _userManager.ChangePhoneNumberAsync(UserId, model.PhoneNumber, model.Code);
            if (result.Succeeded)
            {
                var user = await _userManager.FindByIdAsync(UserId);
                if (user != null)
                {
                    await SignInAsync(user, isPersistent: false);
                }
                return RedirectToAction("Index", new { Message = ManageMessageId.AddPhoneSuccess });
            }
            // If we got this far, something failed, redisplay form
            ModelState.AddModelError("", "Failed to verify phone");
            return View(model);
        }

        //
        // GET: /Account/RemovePhoneNumber
        public async Task<ActionResult> RemovePhoneNumber()
        {
            var result = await _userManager.SetPhoneNumberAsync(UserId, null);
            if (!result.Succeeded)
            {
                return RedirectToAction("Index", new {Message = ManageMessageId.Error});
            }
            var user = await _userManager.FindByIdAsync(UserId);
            if (user != null)
            {
                await SignInAsync(user, isPersistent: false);
            }
            return RedirectToAction("Index", new { Message = ManageMessageId.RemovePhoneSuccess });
        }

        //
        // GET: /Manage/ChangePassword
        public ActionResult ChangePassword()
        {
            return View();
        }

        //
        // POST: /Account/Manage
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var result = await _userManager.ChangePasswordAsync(UserId, model.OldPassword, model.NewPassword);
            if (result.Succeeded)
            {
                var user = await _userManager.FindByIdAsync(UserId);
                if (user != null)
                {
                    await SignInAsync(user, isPersistent: false);
                }
                return RedirectToAction("Index", new { Message = ManageMessageId.ChangePasswordSuccess });
            }
            AddErrors(result);
            return View(model);
        }

        //
        // GET: /Manage/SetPassword
        public ActionResult SetPassword()
        {
            return View();
        }

        //
        // POST: /Manage/SetPassword
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SetPassword(SetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _userManager.AddPasswordAsync(UserId, model.NewPassword);
                if (result.Succeeded)
                {
                    var user = await _userManager.FindByIdAsync(UserId);
                    if (user != null)
                    {
                        await SignInAsync(user, isPersistent: false);
                    }
                    return RedirectToAction("Index", new { Message = ManageMessageId.SetPasswordSuccess });
                }
                AddErrors(result);
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/Manage
        public async Task<ActionResult> ManageLogins(ManageMessageId? message)
        {
            ViewBag.StatusMessage =
                message == ManageMessageId.RemoveLoginSuccess ? "The external login was removed."
                : message == ManageMessageId.Error ? "An error has occurred."
                : "";
            var user = await _userManager.FindByIdAsync(UserId);
            if (user == null)
            {
                return View("Error");
            }
            var userLogins = await _userManager.GetLoginsAsync(UserId);
            var otherLogins = _userManager.GetExternalAuthenticationTypes().Where(auth => userLogins.All(ul => auth.AuthenticationType != ul.LoginProvider)).ToList();
            ViewBag.ShowRemoveButton = user.PasswordHash != null || userLogins.Count > 1;
            return View(new ManageLoginsViewModel
            {
                CurrentLogins = userLogins,
                OtherLogins = otherLogins
            });
        }

        //
        // POST: /Manage/LinkLogin
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LinkLogin(string provider)
        {
            // Request a redirect to the external login provider to link a login for the current user
            return new AccountController.ChallengeResult(provider, Url.Action("LinkLoginCallback", "Manage"), UserId, _userManager);
        }

        //
        // GET: /Manage/LinkLoginCallback
        public async Task<ActionResult> LinkLoginCallback()
        {
            var loginInfo = await _userManager.GetExternalLoginInfoAsync(XsrfKey, UserId.ToString());
            if (loginInfo == null)
            {
                return RedirectToAction("ManageLogins", new { Message = ManageMessageId.Error });
            }
            var result = await _userManager.AddLoginAsync(UserId, loginInfo.Login);
            return result.Succeeded ? RedirectToAction("ManageLogins") : RedirectToAction("ManageLogins", new { Message = ManageMessageId.Error });
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && _userManager != null)
            {
                _userManager.Dispose();
                _userManager = null;
            }
            base.Dispose(disposing);
        }

        #region Helpers
        // Used for XSRF protection when adding external logins
        private const string XsrfKey = "XsrfId";

        private async Task SignInAsync(AppUser user, bool isPersistent)
        {
            _userManager.SignOut(_userManager.ExternalCookie, _userManager.TwoFactorCookie);
            _userManager.SignIn(isPersistent, await _userManager.CreateIdentityAsync(user, _userManager.ApplicationCookie));
        }

        private void AddErrors(ApplicationIdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private bool HasPassword()
        {
            var user = _userManager.FindById(UserId);
            if (user != null)
            {
                return user.PasswordHash != null;
            }
            return false;
        }

        private bool HasPhoneNumber()
        {
            var user = _userManager.FindById(UserId);
            if (user != null)
            {
                return user.PhoneNumber != null;
            }
            return false;
        }

        public enum ManageMessageId
        {
            AddPhoneSuccess,
            ChangePasswordSuccess,
            SetTwoFactorSuccess,
            SetPasswordSuccess,
            RemoveLoginSuccess,
            RemovePhoneSuccess,
            Error
        }

        #endregion
    }
}