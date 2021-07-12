using JwtDemo.Models;
using System.Threading.Tasks;

namespace JwtDemo.Services
{
    public interface IUserService
    {
        Task<string> Register(RegisterRequest request);
        Task<TokenResponse> GetToken(TokenRequest request);
        Task<TokenResponse> GetToken(string refreshToken);
        Task<string> AddRole(AddRoleRequest request);
        Task<ApplicationUser> GetById(string id);
        Task<string> RevokeToken(string token);
    }
}
