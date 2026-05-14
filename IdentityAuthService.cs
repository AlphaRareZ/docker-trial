using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationService;

public class IdentityAuthService : IAuthService
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly AppDbContext _context;
    private readonly JwtSettings _jwtSettings;

    public IdentityAuthService(
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        RoleManager<IdentityRole> roleManager,
        AppDbContext context,
        JwtSettings jwtSettings)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _roleManager = roleManager;
        _context = context;
        _jwtSettings = jwtSettings;
    }

    public async Task<AuthResult> LoginAsync(LoginRequest request)
    {
        try
        {
            // Validate input
            if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
            {
                return new AuthResult
                {
                    Success = false,
                    ErrorMessage = "Email and password are required.",
                    Errors = new List<string> { "Email and password are required." }
                };
            }

            // Find user by email
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return new AuthResult
                {
                    Success = false,
                    ErrorMessage = "Invalid credentials.",
                    Errors = new List<string> { "Invalid email or password." }
                };
            }

            // Check password
            var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);
            if (!result.Succeeded)
            {
                var errors = new List<string>();

                if (result.IsLockedOut)
                    errors.Add("Account is locked out.");
                else if (result.IsNotAllowed)
                    errors.Add("Account is not allowed to sign in.");
                else if (result.RequiresTwoFactor)
                    errors.Add("Two-factor authentication is required.");
                else
                    errors.Add("Invalid email or password.");

                return new AuthResult
                {
                    Success = false,
                    ErrorMessage = errors.First(),
                    Errors = errors
                };
            }

            // Update security stamp to track login
            await _userManager.UpdateSecurityStampAsync(user);

            // Generate tokens
            var appUser = await MapToAppUserAsync(user);
            var token = await GenerateJwtTokenAsync(user);
            var refreshToken = await GenerateRefreshTokenAsync(user.Id);

            return new AuthResult
            {
                Success = true,
                Token = token,
                RefreshToken = refreshToken.Token,
                User = appUser,
                ExpiresAt = DateTime.UtcNow.AddMinutes(_jwtSettings.TokenExpirationMinutes)
            };
        }
        catch (Exception ex)
        {
            return new AuthResult
            {
                Success = false,
                ErrorMessage = "An error occurred during login.",
                Errors = new List<string> { "An unexpected error occurred." }
            };
        }
    }

    public async Task<AuthResult> RegisterAsync(RegisterRequest request)
    {
        try
        {
            // Validate input
            if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
            {
                return new AuthResult
                {
                    Success = false,
                    ErrorMessage = "Email and password are required.",
                    Errors = new List<string> { "Email and password are required." }
                };
            }

            // Create new Identity user
            var user = new IdentityUser
            {
                UserName = request.Email,
                Email = request.Email,
                EmailConfirmed = true // Set to false if you want email confirmation
            };

            // Create user with Identity
            var result = await _userManager.CreateAsync(user, request.Password);

            if (!result.Succeeded)
            {
                return new AuthResult
                {
                    Success = false,
                    ErrorMessage = "Registration failed.",
                    Errors = result.Errors.Select(e => e.Description).ToList()
                };
            }

            // Add custom claims for first/last name
            var claims = new List<Claim>();
            if (!string.IsNullOrWhiteSpace(request.FirstName))
                claims.Add(new Claim(CustomClaimTypes.FirstName, request.FirstName));
            if (!string.IsNullOrWhiteSpace(request.LastName))
                claims.Add(new Claim(CustomClaimTypes.LastName, request.LastName));

            if (claims.Count != 0)
                await _userManager.AddClaimsAsync(user, claims);

            // Add default role
            if (await _roleManager.RoleExistsAsync("User"))
                await _userManager.AddToRoleAsync(user, "User");

            // Generate tokens
            var appUser = await MapToAppUserAsync(user);
            var token = await GenerateJwtTokenAsync(user);
            var refreshToken = await GenerateRefreshTokenAsync(user.Id);

            return new AuthResult
            {
                Success = true,
                Token = token,
                RefreshToken = refreshToken.Token,
                User = appUser,
                ExpiresAt = DateTime.UtcNow.AddMinutes(_jwtSettings.TokenExpirationMinutes)
            };
        }
        catch (Exception ex)
        {
            return new AuthResult
            {
                Success = false,
                ErrorMessage = "An error occurred during registration.",
                Errors = new List<string> { "An unexpected error occurred." }
            };
        }
    }

    public async Task<AuthResult> RefreshTokenAsync(RefreshTokenRequest request)
    {
        try
        {
            var refreshToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(x => x.Token == request.RefreshToken);

            if (refreshToken == null || refreshToken.IsRevoked || refreshToken.ExpiresAt <= DateTime.UtcNow)
            {
                return new AuthResult
                {
                    Success = false,
                    ErrorMessage = "Invalid or expired refresh token.",
                    Errors = new List<string> { "Invalid or expired refresh token." }
                };
            }

            var user = await _userManager.FindByIdAsync(refreshToken.UserId);
            if (user == null)
            {
                return new AuthResult
                {
                    Success = false,
                    ErrorMessage = "User not found.",
                    Errors = new List<string> { "User not found." }
                };
            }

            // Revoke old refresh token
            refreshToken.IsRevoked = true;
            _context.RefreshTokens.Update(refreshToken);
            await _context.SaveChangesAsync();

            // Generate new tokens
            var appUser = await MapToAppUserAsync(user);
            var newToken = await GenerateJwtTokenAsync(user);
            var newRefreshToken = await GenerateRefreshTokenAsync(user.Id);

            return new AuthResult
            {
                Success = true,
                Token = newToken,
                RefreshToken = newRefreshToken.Token,
                User = appUser,
                ExpiresAt = DateTime.UtcNow.AddMinutes(_jwtSettings.TokenExpirationMinutes)
            };
        }
        catch (Exception ex)
        {
            return new AuthResult
            {
                Success = false,
                ErrorMessage = "An error occurred during token refresh.",
                Errors = new List<string> { "An unexpected error occurred." }
            };
        }
    }

    public async Task<bool> LogoutAsync(string refreshToken)
    {
        try
        {
            var token = await _context.RefreshTokens
                .FirstOrDefaultAsync(x => x.Token == refreshToken);

            if (token != null)
            {
                token.IsRevoked = true;
                _context.RefreshTokens.Update(token);
                await _context.SaveChangesAsync();
                return true;
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> RevokeTokenAsync(string refreshToken)
    {
        return await LogoutAsync(refreshToken);
    }

    public async Task<bool> RevokeAllUserTokensAsync(string userId)
    {
        try
        {
            var tokens = await _context.RefreshTokens
                .Where(x => x.UserId == userId && !x.IsRevoked)
                .ToListAsync();

            foreach (var token in tokens)
            {
                token.IsRevoked = true;
            }

            _context.RefreshTokens.UpdateRange(tokens);
            await _context.SaveChangesAsync();
            return true;
        }
        catch
        {
            return false;
        }
    }

    public async Task<AppUser?> GetUserByIdAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        return user != null ? await MapToAppUserAsync(user) : null;
    }

    public async Task<AppUser?> GetUserByEmailAsync(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        return user != null ? await MapToAppUserAsync(user) : null;
    }

    public ClaimsPrincipal? ValidateToken(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_jwtSettings.SecretKey);

            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false, // changed
                ValidIssuer = _jwtSettings.Issuer,
                ValidateAudience = false, // changed
                ValidAudience = _jwtSettings.Audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            var jwtToken = (JwtSecurityToken)validatedToken;
            return new ClaimsPrincipal(new ClaimsIdentity(jwtToken.Claims, "jwt"));
        }
        catch
        {
            return null;
        }
    }

    private async Task<string> GenerateJwtTokenAsync(IdentityUser user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_jwtSettings.SecretKey);

        // Get user claims
        var userClaims = await _userManager.GetClaimsAsync(user);
        var roles = await _userManager.GetRolesAsync(user);

        
        var claims = new List<Claim>
        {
            new("nameid", user.Id), // Use "nameid" instead of ClaimTypes.NameIdentifier
            new("email", user.Email ?? ""),
            new("unique_name", user.UserName ?? ""), // Use "unique_name"
            new("sub", user.Id),
            new("jti", Guid.NewGuid().ToString())
        };

        // Add role claims
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        // Add custom claims
        claims.AddRange(userClaims);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.TokenExpirationMinutes),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature),
            Issuer = _jwtSettings.Issuer,
            Audience = _jwtSettings.Audience
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        var tokenString = tokenHandler.WriteToken(token);
        
        // Debug output
        Console.WriteLine($"Generated token: {tokenString}");
        Console.WriteLine($"Token parts: {tokenString.Split('.').Length}");
        
        return tokenString;
    }

    private async Task<RefreshToken> GenerateRefreshTokenAsync(string userId)
    {
        var refreshToken = new RefreshToken
        {
            Token = GenerateRandomToken(),
            UserId = userId,
            ExpiresAt = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays),
            CreatedAt = DateTime.UtcNow,
            IsRevoked = false
        };

        _context.RefreshTokens.Add(refreshToken);
        await _context.SaveChangesAsync();
        return refreshToken;
    }

    private async Task<AppUser> MapToAppUserAsync(IdentityUser user)
    {
        var claims = await _userManager.GetClaimsAsync(user);
        var roles = await _userManager.GetRolesAsync(user);

        return new AppUser
        {
            Id = user.Id,
            Email = user.Email ?? "",
            UserName = user.UserName ?? "",
            FirstName = claims.FirstOrDefault(x => x.Type == CustomClaimTypes.FirstName)?.Value ?? "",
            LastName = claims.FirstOrDefault(x => x.Type == CustomClaimTypes.LastName)?.Value ?? "",
            CreatedAt = DateTime.UtcNow, // You might want to add this to IdentityUser
            Roles = roles.ToList()
        };
    }

    private static string GenerateRandomToken()
    {
        using var rng = RandomNumberGenerator.Create();
        var randomBytes = new byte[32];
        rng.GetBytes(randomBytes);
        return Convert.ToBase64String(randomBytes);
    }
}