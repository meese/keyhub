using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Data.SqlClient;
using System.Linq;
using System.Net;
using System.Security.Principal;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using KeyHub.Model;
using KeyHub.Model.Definition.Identity;
using Microsoft.Ajax.Utilities;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Host.SystemWeb;
using Microsoft.Owin.Security;
using KeyHub.Data;
using KeyHub.Web.Models;
using KeyHub.Web.ViewModels.User;
using MvcFlash.Core;
using Membership = System.Web.Security.Membership;

namespace KeyHub.Web.Controllers
{
    /// <summary>
    /// 
    /// </summary>
    [Authorize]
    public class AccountController : Controller
    {
        private readonly IDataContextFactory dataContextFactory;
        public AccountController(IDataContextFactory dataContextFactory)
        {
            this.dataContextFactory = dataContextFactory;
        }

        /// <summary>
        /// Get list of users
        /// </summary>
        /// <returns>User index view</returns>
        public ActionResult Index()
        {
            using (var context = dataContextFactory.CreateByUser())
            {
                // Eager loading users (except current user) and roles
                var usersQuery = (from u in context.Users where u.MembershipUserIdentifier != User.Identity.Name select u)
                                 .Include(u => u.Rights.Select(r => r.RightObject))
                                 .OrderBy(u => u.MembershipUserIdentifier);

                var user = context.GetUser(HttpContext.User.Identity);
                var identityUser = dataContextFactory.Create().CreateUserManager().FindById(user.MembershipUserIdentifier);

                var viewModel = new UserIndexViewModel(user, identityUser, usersQuery.ToList());

                return View(viewModel);
            }
        }

        /// <summary>
        /// Create a single User
        /// </summary>
        /// <returns>Create User view</returns>
        [Authorize(Roles = Role.SystemAdmin)]
        public ActionResult Create()
        {
            var viewModel = new UserCreateViewModel(thisOne: true);
            return View(viewModel);
        }

        /// <summary>
        /// Save created User into context and redirect to index
        /// </summary>
        /// <param name="viewModel">Created UserViewModel</param>
        /// <returns>Redirectaction to index if successful</returns>
        [HttpPost, ValidateAntiForgeryToken, Authorize(Roles = Role.SystemAdmin)]
        public ActionResult Create(UserCreateViewModel viewModel)
        {
            if (ModelState.IsValid)
            {
                using (var dataContext = dataContextFactory.Create())
                {
                    var usermanager = dataContext.CreateUserManager();
                    var newMembershipUserIdentifier = Guid.NewGuid().ToString();
                    var keyHubUser = new KeyHubUser
                    {
                        Id = newMembershipUserIdentifier,
                        UserName = viewModel.User.Email,
                        Email = viewModel.User.Email
                    };

                    var user = new User
                    {
                        MembershipUserIdentifier = newMembershipUserIdentifier,
                        AspIdentityUserIdentifier = newMembershipUserIdentifier,
                        Email = viewModel.User.Email
                    };

                    keyHubUser.User = user;
                    var result = usermanager.Create(keyHubUser, viewModel.User.Password);
                    if (result.Succeeded)
                        Flash.Success("New user succesfully created");
                    else
                        AddErrors(result);

                    if (Url.IsLocalUrl(viewModel.RedirectUrl))
                    {
                        return Redirect(viewModel.RedirectUrl);
                    }
                    else
                    {
                        return RedirectToAction("Index", "Home");
                    }
                }
            }
            //Viewmodel invalid, recall create
            return Create();
        }

        /// <summary>
        /// Edit a single User
        /// </summary>
        /// <param name="id">Id if the user to edit</param>
        /// <returns>Edit User view</returns>
        public ActionResult Edit(int id)
        {
            using (var context = dataContextFactory.Create())
            {
                var user = context.Users.FirstOrDefault(x => x.UserId == id);

                if (user == null)
                    return new HttpStatusCodeResult(HttpStatusCode.NotFound);

                if (!User.IsInRole(Role.SystemAdmin) && user.MembershipUserIdentifier != User.Identity.Name)
                    return new HttpStatusCodeResult(HttpStatusCode.Forbidden);

                var viewModel = new UserEditViewModel()
                {
                    UserId = user.UserId,
                    Email = user.Email
                };

                return View(viewModel);
            }
        }

        /// <summary>
        /// Save edited User into context and redirect to index
        /// </summary>
        /// <param name="viewModel">Edited UserViewModel</param>
        /// <returns>Redirectaction to index if successful</returns>
        [HttpPost, ValidateAntiForgeryToken]
        public ActionResult Edit(UserEditViewModel viewModel)
        {
            if (ModelState.IsValid)
            {
                using (var context = dataContextFactory.Create())
                {
                    var user = context.Users.FirstOrDefault(x => x.UserId == viewModel.UserId);

                    if (user == null)
                        return new HttpStatusCodeResult(HttpStatusCode.NotFound);

                    if (!User.IsInRole(Role.SystemAdmin) && user.MembershipUserIdentifier != User.Identity.Name)
                        return new HttpStatusCodeResult(HttpStatusCode.Forbidden);

                    //Email can always be updated
                    user.Email = viewModel.Email;
                    context.SaveChanges();

                    return RedirectToAction("Index");
                }
            }

            return Edit(viewModel.UserId);
        }

        /// <summary>
        /// Login to KeyHub
        /// </summary>
        /// <returns></returns>
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = (!String.IsNullOrEmpty(returnUrl)) ? returnUrl : Url.Action("Index", "Home", null, "http");
            return View();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost, ValidateAntiForgeryToken]
        public ActionResult Login(LoginViewModel model, string returnUrl)
        {
            if (ModelState.IsValid)
            {


                using (var dataContext = dataContextFactory.Create())
                {
                    var signInManager = new KeyHubSignInManager(dataContext.CreateUserManager(),
                        HttpContext.GetOwinContext().Authentication);
                    if (!ModelState.IsValid)
                    {
                        return View(model);
                    }

                    // This doen't count login failures towards lockout only two factor authentication
                    // To enable password failures to trigger lockout, change to shouldLockout: true
                    var result = signInManager.PasswordSignIn(model.Email, model.Password, model.RememberMe,
                        shouldLockout: false);
                    switch (result)
                    {
                        case SignInStatus.Success:
                            if (Url.IsLocalUrl(returnUrl))
                            {
                                return Redirect(returnUrl);
                            }
                            else
                            {
                                return RedirectToAction("Index", "Home");
                            }
                        case SignInStatus.LockedOut:
                            ModelState.AddModelError("", "You have been locked out of your account");
                            return View(model);
                        case SignInStatus.Failure:
                        default:
                            ModelState.AddModelError("", "The user name or password provided is incorrect");
                            return View(model);
                    }
                }
            }
            // If we got this far, something failed, redisplay form
            return View(model);
        }



        /// <summary>
        /// Log off
        /// </summary>
        /// <returns>Redirect to home</returns>
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut();
            return RedirectToAction("Index", "Home");
        }

        /// <summary>
        /// Register a new user
        /// </summary>
        /// <param name="returnUrl">Url to return to upon successfull registration</param>
        /// <returns>Register user view</returns>
        [AllowAnonymous]
        public ActionResult Register(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        /// <summary>
        /// Register user and redirect to return URL if specified
        /// </summary>
        /// <param name="model">RegisterViewModel for new user</param>
        /// <param name="returnUrl">Url to redirect to after successfull registration</param>
        /// <returns>Redirect to Index, or ReturnUrl if specified</returns>
        [HttpPost, AllowAnonymous, ValidateAntiForgeryToken]
        public ActionResult Register(RegisterViewModel model, string returnUrl)
        {
            if (ModelState.IsValid)
            {

                // Attempt to register the user
                try
                {
                    using (var dataContext = dataContextFactory.Create())
                    {
                        var usermanager = dataContext.CreateUserManager();
                        var newMembershipUserIdentifier = Guid.NewGuid().ToString();
                        var keyHubUser = new KeyHubUser
                        {
                            Id = newMembershipUserIdentifier,
                            UserName = model.Email,
                            Email = model.Email
                        };

                        var user = new User
                        {
                            MembershipUserIdentifier = newMembershipUserIdentifier,
                            AspIdentityUserIdentifier = newMembershipUserIdentifier,
                            Email = model.Email
                        };

                        keyHubUser.User = user;
                        var result = usermanager.Create(keyHubUser, model.Password);
                        if (result.Succeeded)
                        {
                            if (Url.IsLocalUrl(returnUrl))
                            {
                                return Redirect(returnUrl);
                            }
                            else
                            {
                                return RedirectToAction("Index", "Home");
                            }
                        }
                        else
                        {
                            AddErrors(result);
                        }
                    }
                }

                catch (Exception exception)
                {
                    if (exception.Message.Contains("IX_Email") && exception.Message.Contains("duplicate"))
                    {
                        ModelState.AddModelError("",
                            "The email address registered is already in use on this site using a different login method.  "
                            + "Please login with the original login method used for that email.  "
                            + "Then you may associate other login methods with your account.  ");

                        return View(model);
                    }
                    throw;
                }

            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        /// <summary>
        /// Change password
        /// </summary>
        /// <returns>Change password view</returns>
        public ActionResult ChangePassword()
        {
            using (var dataContext = dataContextFactory.Create())
            {
                var viewModel = new ChangePasswordViewModel(dataContext.GetUser(User.Identity).Email);
                return View(viewModel);
            }
        }

        /// <summary>
        /// Change password
        /// </summary>
        /// <param name="model">Changed password model</param>
        /// <returns></returns>
        [HttpPost, ValidateAntiForgeryToken]
        public ActionResult ChangePassword(ChangePasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                using (var userManager = dataContextFactory.Create().CreateUserManager())
                {
                    var result = userManager.ChangePassword(User.Identity.GetUserId(), model.OldPassword,
                        model.NewPassword);

                    if (result.Succeeded)
                    {
                        Flash.Success("Your password has been changed.");
                        return RedirectToAction("Index");
                    }
                    else
                    {
                        AddErrors(result);
                    }
                }
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }



        #region OpenAuth
        /// <summary>
        /// Get a list of external logins
        /// </summary>
        /// <param name="returnUrl">Return url to go to upon successfull login</param>
        /// <returns></returns>
        [AllowAnonymous]
        public ActionResult ExternalLoginsList(string returnUrl)
        {
            var loginProviders = HttpContext.GetOwinContext().Authentication.GetExternalAuthenticationTypes();
            ViewBag.ReturnUrl = returnUrl;
            return PartialView("_ExternalLoginsListPartial", loginProviders);
        }

        /// <summary>
        /// Login from external
        /// </summary>
        /// <param name="provider">Provider to login with</param>
        /// <param name="returnUrl">Url to go to upon successfull login</param>
        /// <returns></returns>
        [HttpPost]
        [AllowAnonymous]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            return new ChallengeResult(provider, Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
        }

        /// <summary>
        /// Handle external login from OpenID provider
        /// </summary>
        /// <param name="returnUrl">Url to go to upon successfull login</param>
        /// <returns></returns>
        [AllowAnonymous]
        public ActionResult ExternalLoginCallback(string returnUrl)
        {
            var loginInfo = AuthenticationManager.GetExternalLoginInfo();
            if (loginInfo == null)
            {
                return View("ExternalLoginFailure");
            }
            using (var dataContext = dataContextFactory.Create())
            {
                // Sign in the user with this external login provider if the user already has a login
                var signInManager = new KeyHubSignInManager(dataContext.CreateUserManager(),
                    HttpContext.GetOwinContext().Authentication);
                var resultLogin = signInManager.ExternalSignIn(loginInfo, isPersistent: false);
                switch (resultLogin)
                {
                    case SignInStatus.Success:
                        return RedirectTo(returnUrl);
                    case SignInStatus.LockedOut:
                    case SignInStatus.RequiresVerification:
                        return RedirectToAction("ExternalLoginFailure");
                    case SignInStatus.Failure:
                    default:
                        break;
                }
            }

            if (User.Identity.IsAuthenticated)
            {
                // If the current user is logged in add the new account
                using (var db = dataContextFactory.Create())
                {
                    var userManager = db.CreateUserManager();

                    // Add to asp identity external login table
                    var resultAddLogin = userManager.AddLogin(User.Identity.GetUserId(), loginInfo.Login);
                    if (!resultAddLogin.Succeeded)
                        AddErrors(resultAddLogin);
                    return RedirectToAction("Index");
                }
            }

            // Get the information about the user from the external login provider
            var userName = loginInfo.ExternalIdentity.GetUserName();
            var loginData = loginInfo.Login;
            var email = loginInfo.Email;

            //create our user and add external login
            try
            {
                // Insert a new user into the database
                using (var db = dataContextFactory.Create())
                {
                    var userManager = db.CreateUserManager();
                    var membershipUserIdentifier = Guid.NewGuid().ToString();

                    // Add to our user table
                    var user = new User { MembershipUserIdentifier = membershipUserIdentifier, Email = email };
                    db.Users.Add(user);

                    // Add to asp identity table
                    var keyHubUser = new KeyHubUser() { UserName = userName, Email = email, Id = membershipUserIdentifier, User = user };
                    var result = userManager.Create(keyHubUser);
                    if (!result.Succeeded)
                    {
                        AddErrors(result);
                        return RedirectTo(returnUrl);
                    }

                    // Add to asp identity external login table
                    var resultAddLogin = userManager.AddLogin(membershipUserIdentifier, loginInfo.Login);

                    if (resultAddLogin.Succeeded)
                    {
                        var signInManager = new KeyHubSignInManager(db.CreateUserManager(), HttpContext.GetOwinContext().Authentication);
                        signInManager.SignIn(keyHubUser, isPersistent: false, rememberBrowser: false);
                        db.SaveChanges();

                        return RedirectTo(returnUrl);
                    }

                    AddErrors(resultAddLogin);
                }
            }
            catch (DbUpdateException e)
            {
                var innerException1 = e.InnerException as System.Data.Entity.Core.UpdateException;
                if (innerException1 == null)
                    throw;

                var innerException2 = innerException1.InnerException as SqlException;
                if (innerException2 == null)
                    throw;

                var innerExceptionMessage = innerException2.Message ?? "";

                if (innerExceptionMessage.Contains("IX_Email") && innerExceptionMessage.Contains("duplicate"))
                {
                    Flash.Error("The email address used to login is already in use on this site using a different login method.  "
                        + "Please login with the original login method used for that email.  "
                        + "Then you may associate other login methods with your account.  ");

                    return RedirectToAction("Login");
                }
                else
                {
                    throw;
                }
            }

            return RedirectTo(returnUrl);
        }

        /// <summary>
        /// Show login failure
        /// </summary>
        /// <returns></returns>
        [AllowAnonymous]
        public ActionResult ExternalLoginFailure()
        {
            return View();
        }

        public ActionResult LinkAccount()
        {
            using (var context = dataContextFactory.Create())
            {
                var model = LinkAccountModel.ForUser(context, User.Identity);
                return View("LinkAccount", model);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LinkAccount(string provider)
        {
            return new ChallengeResult(provider, Url.Action("LinkAccountCallback", new { externalProvider = provider }));
        }

        public ActionResult LinkAccountCallback(string externalProvider)
        {
            var loginInfo = AuthenticationManager.GetExternalLoginInfo(XsrfKey, User.Identity.GetUserId());

            if (loginInfo == null)
            {
                Flash.Error("The account was unable to be linked.");
                return RedirectToAction("LinkAccount");
            }

            using (var userManager = dataContextFactory.Create().CreateUserManager())
            {
                var result = userManager.AddLogin(User.Identity.GetUserId(), loginInfo.Login);

                if (!result.Succeeded)
                {
                    AddErrors(result);
                    Flash.Error("The account was unable to be linked.");
                }
                else
                    Flash.Success("Your " + externalProvider + " login has been linked.");

            }
            return RedirectToAction("LinkAccount");

        }

        public class UnlinkLoginModel
        {
            public string Provider { get; set; }
        }

        public ActionResult UnlinkLogin(string provider)
        {
            return View(new UnlinkLoginModel() { Provider = provider });
        }

        [HttpPost, ValidateAntiForgeryToken, ActionName("UnlinkLogin")]
        public ActionResult UnlinkLogin_Post(string provider)
        {
            using (var context = dataContextFactory.Create())
            {
                var model = LinkAccountModel.ForUser(context, User.Identity);

                if (!model.AllowRemovingLogin)
                {
                    Flash.Error(
                        "The login could not be unlinked because it is the last login available for this account.");
                }
                else
                {
                    var usermanager = context.CreateUserManager();
                    var user =
                        usermanager.Users.FirstOrDefault(u => u.Id == User.Identity.GetUserId());
                    var providerAccount = user.Logins.Single(l => l.LoginProvider.ToLower() == provider.ToLower());

                    var result = usermanager.RemoveLogin(user.Id,new UserLoginInfo(providerAccount.LoginProvider,providerAccount.ProviderKey));
                    if (result.Succeeded)
                    {
                        Flash.Success("Your " + provider + " login has been unlinked");
                    }
                    else
                    {
                        AddErrors(result);
                        Flash.Error("The account could not be unlinked.");
                    }
                }
            }

            return RedirectToAction("LinkAccount");
        }

        #endregion

        #region Helpers
        /// <summary>
        /// Redirect to url or home
        /// </summary>
        /// <param name="url">Url to redirect to</param>
        /// <returns></returns>
        private ActionResult RedirectTo(string url)
        {
            if (Url.IsLocalUrl(url))
            {
                return Redirect(url);
            }
            return RedirectToAction("Index", "Home");
        }

        private const string XsrfKey = "XsrfId";

        internal class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
                if (UserId != null)
                {
                    properties.Dictionary[XsrfKey] = UserId;
                }
                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
            }
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }
        #endregion
    }
}
