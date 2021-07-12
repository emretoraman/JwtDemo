using JwtDemo.Constants;
using JwtDemo.Data;
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
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static JwtDemo.Constants.Authorization;

namespace JwtDemo.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly Jwt _jwt;
        private readonly ApplicationDbContext _context;

        public UserService(UserManager<ApplicationUser> userManager, IOptions<Jwt> jwt, ApplicationDbContext context)
        {
            _userManager = userManager;
            _jwt = jwt.Value;
            _context = context;
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

            RefreshToken refreshToken = user.RefreshTokens.FirstOrDefault(t => t.IsActive);
            if (refreshToken == null)
            {
                refreshToken = CreateRefreshToken();
                user.RefreshTokens.Add(refreshToken);
                _context.Update(user);
                await _context.SaveChangesAsync();
            }

            return new TokenResponse
            {
                IsAuthenticated = true,
                UserName = user.UserName,
                Email = user.Email,
                Roles = (await _userManager.GetRolesAsync(user)).ToList(),
                Token = new JwtSecurityTokenHandler().WriteToken(await CreateJwtToken(user)),
                RefreshToken = refreshToken.Token,
                RefreshTokenExpiration = refreshToken.Expires
            };
        }

        public async Task<TokenResponse> GetToken(string refreshToken)
        {
            ApplicationUser user = _context.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == refreshToken));
            if (user == null)
            {
                return new TokenResponse { Message = "Token did not match any users" };
            }

            RefreshToken currentRefreshToken = user.RefreshTokens.Single(t => t.Token == refreshToken);
            if (!currentRefreshToken.IsActive)
            {
                return new TokenResponse { Message = "Token is not active" };
            }

            currentRefreshToken.Revoked = DateTime.UtcNow;

            RefreshToken newRefreshToken = CreateRefreshToken();
            user.RefreshTokens.Add(newRefreshToken);
            _context.Update(user);
            await _context.SaveChangesAsync();

            return new TokenResponse
            {
                IsAuthenticated = true,
                UserName = user.UserName,
                Email = user.Email,
                Roles = (await _userManager.GetRolesAsync(user)).ToList(),
                Token = new JwtSecurityTokenHandler().WriteToken(await CreateJwtToken(user)),
                RefreshToken = newRefreshToken.Token,
                RefreshTokenExpiration = newRefreshToken.Expires
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

        public async Task<ApplicationUser> GetById(string id)
        {
            return await _context.Users.FindAsync(id);
        }

        public async Task<string> RevokeToken(string token)
        {
            ApplicationUser user = _context.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));
            if (user == null)
            {
                return "Token did not match any users";
            }

            RefreshToken currentRefreshToken = user.RefreshTokens.Single(t => t.Token == token);
            if (!currentRefreshToken.IsActive)
            {
                return "Token is not active";
            }

            currentRefreshToken.Revoked = DateTime.UtcNow;
            _context.Update(user);
            await _context.SaveChangesAsync();

            return "Token revoked";
        }

        private static RefreshToken CreateRefreshToken()
        {
            byte[] randomNumber = new byte[32];

            using RNGCryptoServiceProvider generator = new();
            generator.GetBytes(randomNumber);

            return new RefreshToken
            {
                Token = Convert.ToBase64String(randomNumber),
                Expires = DateTime.UtcNow.AddDays(10),
                Created = DateTime.UtcNow
            };
        }

        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            IList<Claim> userClaims = await _userManager.GetClaimsAsync(user);

            IList<string> roles = await _userManager.GetRolesAsync(user);
            List<Claim> roleClaims = roles.Select(r => new Claim("roles", r)).ToList();

            IEnumerable<Claim> claims =
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
