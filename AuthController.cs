using System.Runtime.InteropServices.JavaScript;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationService;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var result = await _authService.LoginAsync(request);

        if (!result.Success)
            return BadRequest();

        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Expires = result.ExpiresAt,
            Path = "/"
        };

        Response.Cookies.Append(
            "accessToken",
            result.Token!,
            new CookieOptions()
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Expires = result.ExpiresAt,
                Path = "/"
            }
        );

        Response.Cookies.Append(
            "refreshToken",
            result.RefreshToken!,
            new CookieOptions()
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Expires = DateTime.UtcNow.AddDays(30),
                Path = "/"
            }
        );

        return Ok(new
        {
            user = result.User
        });
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        var result = await _authService.RegisterAsync(request);

        if (!result.Success)
            return BadRequest(new
            {
                message = result.ErrorMessage,
                errors = result.Errors
            });

        return Ok(new
        {
            token = result.Token,
            refreshToken = result.RefreshToken,
            expiresAt = result.ExpiresAt,
            user = result.User
        });
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> RefreshToken()
    {
        var refreshToken =
            Request.Cookies["refreshToken"];

        if (string.IsNullOrEmpty(refreshToken))
        {
            return Unauthorized(new
            {
                message = "Refresh token missing"
            });
        }

        var result =
            await _authService.RefreshTokenAsync(
                new RefreshTokenRequest
                {
                    RefreshToken = refreshToken
                });

        if (!result.Success)
        {
            return Unauthorized(new
            {
                message = result.ErrorMessage
            });
        }

        Response.Cookies.Append(
            "accessToken",
            result.Token!,
            new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Expires = result.ExpiresAt,
                Path = "/"
            });

        Response.Cookies.Append(
            "refreshToken",
            result.RefreshToken!,
            new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Expires = DateTime.UtcNow.AddDays(30),
                Path = "/"
            });

        return Ok(new
        {
            success = true
        });
    }

    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout([FromBody] RefreshTokenRequest request)
    {
        var success = await _authService.LogoutAsync(request.RefreshToken);

        if (success)
            return Ok(new { message = "Logged out successfully" });
        return BadRequest(new { message = "Logout failed" });
    }

    [HttpPost("revoke-all-tokens")]
    [Authorize]
    public async Task<IActionResult> RevokeAllTokens()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var success = await _authService.RevokeAllUserTokensAsync(userId!);

        if (success)
            return Ok(new { message = "All tokens revoked successfully" });
        return BadRequest(new { message = "Failed to revoke tokens" });
    }
    [HttpGet("me")]
    //[Authorize(policy:"AdminOnly")]
    public async Task<IActionResult> GetCurrentUser()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var user = await _authService.GetUserByIdAsync(userId!);
        if (user == null)
            return NotFound();
        return Ok(user);
    }
}