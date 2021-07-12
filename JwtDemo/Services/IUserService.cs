using JwtDemo.Models;
using System.Threading.Tasks;

namespace JwtDemo.Services
{
    public interface IUserService
    {
        Task<string> Register(RegisterRequest request);
        Task<TokenResponse> GetToken(TokenRequest request);
        Task<string> AddRole(AddRoleRequest request);
    }
}
