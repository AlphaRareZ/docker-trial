using System.Security.Claims;

namespace AuthenticationService;

public interface IAuthService
{
    Task<AuthResult> LoginAsync(LoginRequest request);
    Task<AuthResult> RegisterAsync(RegisterRequest request);
    Task<AuthResult> RefreshTokenAsync(RefreshTokenRequest request);
    Task<bool> LogoutAsync(string refreshToken);
    Task<AppUser?> GetUserByIdAsync(string userId);
    Task<AppUser?> GetUserByEmailAsync(string email);
    ClaimsPrincipal? ValidateToken(string token);
    Task<bool> RevokeTokenAsync(string refreshToken);
    Task<bool> RevokeAllUserTokensAsync(string userId);
}