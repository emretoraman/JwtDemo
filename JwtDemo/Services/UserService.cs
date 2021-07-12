using JwtDemo.Constants;
using JwtDemo.Models;
using JwtDemo.Settings;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using static JwtDemo.Constants.Authorization;

namespace JwtDemo.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly Jwt _jwt;

        public UserService(UserManager<ApplicationUser> userManager, IOptions<Jwt> jwt)
        {
            _userManager = userManager;
            _jwt = jwt.Value;
        }

        public async Task<string> Register(RegisterRequest request)
        {
            ApplicationUser user = new()
            {
                UserName = request.UserName,
                Email = request.Email,
                FirstName = request.FirstName,
                LastName = request.LastName
            };

            ApplicationUser existing = await _userManager.FindByEmailAsync(request.Email);
            if (existing != null)
            {
                return $"Email {user.Email} is already registered";
            }

            IdentityResult result = await _userManager.CreateAsync(user, request.Password);
            if (!result.Succeeded)
            {
                string errors = string.Join("\n", result.Errors.Select(e => $"({e.Code}) {e.Description}"));
                return $"User could not be registered:\n{errors}";
            } 

            await _userManager.AddToRoleAsync(user, Authorization.DefaultRole.ToString());

            return $"User registered with username {user.UserName}";
        }

        public async Task<TokenResponse> GetToken(TokenRequest request)
        {
            ApplicationUser user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, request.Password))
            {
                return new TokenResponse { Message = "Incorrect credentials" };
            }

            return new TokenResponse
            {
                IsAuthenticated = true,
                UserName = user.UserName,
                Email = user.Email,
                Roles = (await _userManager.GetRolesAsync(user)).ToList(),
                Token = new JwtSecurityTokenHandler().WriteToken(await CreateJwtToken(user))
            };
        }

        public async Task<string> AddRole(AddRoleRequest request)
        {
            ApplicationUser user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return $"No accounts registered with {request.Email}";
            }

            if (!Enum.TryParse(request.Role, out Role role))
            {
                return $"Role {request.Role} not found";
            }

            await _userManager.AddToRoleAsync(user, role.ToString());

            return $"Added {request.Role} to user {request.Email}";
        }

        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            IList<Claim> userClaims = await _userManager.GetClaimsAsync(user);

            IList<string> roles = await _userManager.GetRolesAsync(user);
            List<Claim> roleClaims = roles.Select(r => new Claim("roles", r)).ToList();

            var claims =
                new[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim("uid", user.Id)
                }
                .Union(userClaims)
                .Union(roleClaims);

            SymmetricSecurityKey symmetricSecurityKey = new(Encoding.UTF8.GetBytes(_jwt.Key));
            SigningCredentials signingCredentials = new(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            return new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwt.DurationInMinutes),
                signingCredentials: signingCredentials
            );
        }
    }
}
