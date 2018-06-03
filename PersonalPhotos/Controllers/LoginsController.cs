using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Internal;
using PersonalPhotos.Interfaces;
using PersonalPhotos.ViewModels;

namespace PersonalPhotos.Controllers
{
    public class LoginsController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleInManager;
        private readonly IEmail _email;
        public LoginsController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager
            , RoleManager<IdentityRole> roleInManager, IEmail email)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleInManager = roleInManager;
            _email = email;
        }

        public IActionResult Index(string returnUrl = null)
        {
            var model = new LoginViewModel { ReturnUrl = returnUrl };
            return View("Index", model);
        }

        [HttpPost]
        public async Task<IActionResult> Index(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("", "Invalid login detils");
                return View("Index", model);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || !user.EmailConfirmed)
            {
                ModelState.AddModelError(string.Empty, "User not found or User is not confirm.");
                return View();
            }

            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);
            if (!result.Succeeded)
            {
                if (result == Microsoft.AspNetCore.Identity.SignInResult.TwoFactorRequired)
                {
                    return RedirectToAction("MfaLogin");
                }
                ModelState.AddModelError(string.Empty, "Username and/or Password are incorrect.");
                return View();
            }

            var claims = new List<Claim> { new Claim("Over18Claim", "True") };
            var claimIdentity = new ClaimsIdentity(claims);
            User.AddIdentity(claimIdentity);

            if (!string.IsNullOrEmpty(model.ReturnUrl))
            {
                return Redirect(model.ReturnUrl);
            }
            return RedirectToAction("Display", "Photos");
        }

        public IActionResult Create()
        {
            return View("Create");
        }

        [HttpPost]
        public async Task<IActionResult> Create(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("", "Invalid user details");
                return View(model);
            }

            if (!await _roleInManager.RoleExistsAsync("Editor"))
            {
                await _roleInManager.CreateAsync(new IdentityRole("Editor"));
            }

            var user = new IdentityUser
            {
                UserName = model.Email,
                Email = model.Email
            };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, $"{error.Code}:{error.Description}");
                }
                return View();
            }

            // It does make any sense this because the user is new
            //if (!User.IsInRole("Editor"))
            //{
            //    await _userManager.AddToRoleAsync(user, "Editor");
            //}
            await _userManager.AddToRoleAsync(user, "Editor");
            //await _userManager.AddToRolesAsync(user, new[] {"Editor","Creator"});

            var token = _userManager.GenerateEmailConfirmationTokenAsync(user);
            var scheme = Url.ActionContext.HttpContext.Request.Scheme;
            var url = Url.Action("Confirmation", "Logins", new { id = user.Id, token = token.Result }, scheme);
            var emailBody = $"Please, confirm your email by clicking on the link below<br>{url}";
            const string subject = "Please, confirm your email address!";
            await _email.Send(model.Email, emailBody, subject);
            return RedirectToAction("Index");
        }

        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index");
        }

        public async Task<IActionResult> Confirmation(string id, string token)
        {
            var user = await _userManager.FindByIdAsync(id);
            var confirm = await _userManager.ConfirmEmailAsync(user, token);
            if (confirm.Succeeded)
            {
                var is2FaEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
                if (!is2FaEnabled)
                {
                    return RedirectToAction("Setup2Fa");
                }
                return RedirectToAction("Index");
            }
            ViewBag["Error"] = "Error with validating the emails address";
            return View();
        }

        public IActionResult ResetPassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("", "Invalid Email Address");
                return View(model);
            }
            var user = await _userManager.FindByEmailAsync(model.EmailAddress);
            if (user == null || !user.EmailConfirmed)
            {
                ModelState.AddModelError(string.Empty, "User not found or User is not confirm.");
                return View();
            }
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            string scheme = Url.ActionContext.HttpContext.Request.Scheme;
            var url = Url.Action("ChangePassword", "Logins", new { userId = user.Id, token }, scheme);
            var emailBody = $"Please, click on the link below to change your new password<br>{url}";
            const string subject = "Please, confirm your new password!";
            await _email.Send(model.EmailAddress, emailBody, subject);
            return RedirectToAction("Index");
        }

        public async Task<IActionResult> ChangePassword(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                ViewBag["Error"] = "User is not valid.";
                return View("Confirmation");
            }
            var model = new ChangePasswordViewModel
            {
                EmailAddress = user.Email,
                Token = token
            };
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("", "Errors in Page!");
                return View(model);
            }
            var user = await _userManager.FindByEmailAsync(model.EmailAddress);
            if (user == null || !user.EmailConfirmed)
            {
                ModelState.AddModelError(string.Empty, "User not found or User is not confirm.");
                return View();
            }
            var resetPasswordResult = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
            if (!resetPasswordResult.Succeeded)
            {
                ModelState.AddModelError(string.Empty, "The new Password has not been able to be changed. Please retry in a few minutes.");
                return View();
            }
            return RedirectToAction("Index");
        }

        [Authorize]
        public async Task<IActionResult> Setup2Fa()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                var authKey = await _userManager.GetAuthenticatorKeyAsync(user);
                if (string.IsNullOrEmpty(authKey))
                {
                    await _userManager.ResetAuthenticatorKeyAsync(user);
                    authKey = await _userManager.GetAuthenticatorKeyAsync(user);
                }
                var model = new MfaCreateViewModel
                {
                    AuthKey = authKey,
                    FormattedAuthKey = FormatAuthKey(authKey)
                };
                return View(model);
            }
            return View();
        }

        private static string FormatAuthKey(string authKey)
        {
            const int chunkLength = 5;
            var newAuthKey = new StringBuilder();
            while (authKey.Length > 0)
            {
                var length = chunkLength > authKey.Length ? authKey.Length : chunkLength;
                newAuthKey.Append(authKey.Substring(0, length) + " ");
                authKey = authKey.Remove(0, length);
            }
            return newAuthKey.ToString();
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> Setup2Fa(MfaCreateViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("", "Errors in Page!");
                return View(model);
            }
            var user = await _userManager.GetUserAsync(User);
            if (user == null || !user.EmailConfirmed)
            {
                ModelState.AddModelError(string.Empty, "User not found or User is not confirm.");
                return View(model);
            }
            var isCodeCorrect = await _userManager.VerifyTwoFactorTokenAsync(user,
                _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
            if (!isCodeCorrect)
            {
                ModelState.AddModelError(string.Empty, "The code did not match they auth key! Please, try it again");
                return View(model);
            }
            await _userManager.SetTwoFactorEnabledAsync(user, true);
            return RedirectToAction("Index");
        }

        public IActionResult MfaLogin()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> MfaLogin(MfaLoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("", "Errors in Page!");
                return View(model);
            }
            var result = await _signInManager.TwoFactorSignInAsync(_userManager.Options.Tokens.AuthenticatorTokenProvider,
                model.Code, true, true);
            if (!result.Succeeded)
            {
                ModelState.AddModelError(string.Empty, "Your code could not be validated. Try again.");
                return View(model);
            }
            return RedirectToAction("Index");
        }

        [HttpPost]
        public IActionResult ExternalLogin(string provider, string returnUrl)
        {
            var redirectUrl = Url.Action("ExternalLoginCallBack", "Logins", new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Challenge(properties, provider);
        }

        public async Task<IActionResult> ExternalLoginCallBack(string returnUrl = null, string remoteError = null)
        {
            if (!string.IsNullOrEmpty(remoteError))
            {
                return RedirectToAction("Index");
            }

            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction("Index");
            }

            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true, true);

            if (result.Succeeded)
            {
                return RedirectToAction("Display", "Photos");
            }

            var emailAddress = info.Principal.FindFirstValue(ClaimTypes.Email);
            var user = new IdentityUser
            {
                Email = emailAddress,
                UserName = emailAddress,
                SecurityStamp = new Guid().ToString()
            };
            var identityUser = await _userManager.FindByEmailAsync(emailAddress);
            if (identityUser == null)
            {
                await _userManager.CreateAsync(user);
            }

            var logins = await _userManager.GetLoginsAsync(user);
            if (logins == null ||
                !logins.Any(x => x.LoginProvider == info.LoginProvider && x.ProviderKey == info.ProviderKey))
            {
                await _userManager.AddLoginAsync(user, info);
            }

            await _signInManager.SignInAsync(user, true);

            if (!string.IsNullOrEmpty(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Display", "Photos");

        }
    }
}