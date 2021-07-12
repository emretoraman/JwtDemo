using JwtDemo.Models;
using JwtDemo.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace JwtDemo.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;

        public UserController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterRequest request)
        {
            string response = await _userService.Register(request);
            return Ok(response);
        }

        [HttpPost("token")]
        public async Task<IActionResult> GetToken(TokenRequest request)
        {
            TokenResponse response = await _userService.GetToken(request);

            SetRefreshTokenInCookie(response.RefreshToken, response.RefreshTokenExpiration);
            return Ok(response);
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken()
        {
            string refreshToken = Request.Cookies["refreshToken"];
            TokenResponse response = await _userService.GetToken(refreshToken);

            SetRefreshTokenInCookie(response.RefreshToken, response.RefreshTokenExpiration);
            return Ok(response);
        }

        [HttpPost("addrole")]
        [Authorize(Roles = "Administrator")]
        public async Task<IActionResult> AddRole(AddRoleRequest request)
        {
            string response = await _userService.AddRole(request);
            return Ok(response);
        }

        [HttpGet("{id:Guid}/tokens")]
        [Authorize(Roles = "Administrator")]
        public async Task<IActionResult> GetRefreshTokens(Guid id)
        {
            ApplicationUser user = await _userService.GetById(id.ToString());
            return Ok(user.RefreshTokens);
        }

        [HttpPost("revoke-token")]
        [Authorize(Roles = "Administrator")]
        public async Task<IActionResult> RevokeToken(RevokeTokenRequest request)
        {
            string response = await _userService.RevokeToken(request.Token);
            return Ok(response);
        }

        [HttpPost("revoke-my-token")]
        [Authorize]
        public async Task<IActionResult> RevokeMyToken()
        {
            string response = await _userService.RevokeToken(Request.Cookies["refreshToken"]);
            return Ok(response);
        }

        private void SetRefreshTokenInCookie(string token, DateTime expires)
        {
            if (string.IsNullOrWhiteSpace(token)) return;

            CookieOptions cookieOptions = new()
            {
                HttpOnly = true,
                Expires = expires,
            };
            Response.Cookies.Append("refreshToken", token, cookieOptions);
        }
    }
}
