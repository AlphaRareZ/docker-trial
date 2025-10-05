namespace AuthenticationService;

public class AuthResult
{
    public bool Success { get; set; }
    public string Token { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public AppUser? User { get; set; }
    public string ErrorMessage { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public List<string> Errors { get; set; } = new();
}