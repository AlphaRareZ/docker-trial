using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
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
            return BadRequest(new
            {
                message = result.ErrorMessage,
                errors = result.Errors
            });
        var cookieOptions = new CookieOptions()
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Expires = result.ExpiresAt
        };
        Response.Cookies.Append(
            "accessToken",
            result.Token!,
            cookieOptions
        );

        Response.Cookies.Append(
            "refreshToken",
            result.RefreshToken!,
            cookieOptions
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
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        var result = await _authService.RefreshTokenAsync(request);

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
            expiresAt = result.ExpiresAt
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
    [Authorize(policy: "AdminOnly")]
    public async Task<IActionResult> GetCurrentUser()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var user = await _authService.GetUserByIdAsync(userId!);
        if (user == null)
            return NotFound();
        return Ok(user);
    }
    
    /*
    [HttpGet("google-login")]
    public IActionResult GoogleLogin()
    {
        var properties = new AuthenticationProperties
        {
            RedirectUri = Url.Action(nameof(GoogleResponse))
        };

        return Challenge(properties, GoogleDefaults.AuthenticationScheme);
    }
    [HttpGet("google-response")]
    public async Task<IActionResult> GoogleResponse()
    {
        var result = await HttpContext.AuthenticateAsync(
            CookieAuthenticationDefaults.AuthenticationScheme);

        if (!result.Succeeded)
            return BadRequest("Google auth failed");

        var claims = result.Principal!.Claims;

        var email = claims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value;
        var name = claims.FirstOrDefault(x => x.Type == ClaimTypes.Name)?.Value;

        // 1. create or get user from DB
        var user = await _authService.FindOrCreateGoogleUser(email!, name!);

        // 2. generate your JWT
        var jwt = _jwtService.GenerateToken(user);

        var refreshToken = _jwtService.GenerateRefreshToken(user);

        // 3. set cookies
        Response.Cookies.Append("accessToken", jwt, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Path = "/"
        });

        Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Path = "/"
        });

        // 4. redirect to frontend
        return Redirect("http://localhost:3000/dashboard");
    }*/
}