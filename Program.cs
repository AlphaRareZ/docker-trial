using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;
using System.Text;
using AuthenticationService;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// 1. Add services to the container
builder.Services.AddControllers();

// Add Identity Auth Service (includes DbContext and Identity setup)
builder.Services.AddIdentityAuthService(builder.Configuration);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApi();

// Configure JWT Authentication
builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme =
            JwtBearerDefaults.AuthenticationScheme;

        options.DefaultChallengeScheme =
            JwtBearerDefaults.AuthenticationScheme;

        options.DefaultScheme =
            JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        var secretKey =
            builder.Configuration["JwtSettings:SecretKey"];

        var issuer =
            builder.Configuration["JwtSettings:Issuer"];

        var audience =
            builder.Configuration["JwtSettings:Audience"];

        if (string.IsNullOrEmpty(secretKey) ||
            secretKey.Length < 32)
        {
            throw new InvalidOperationException(
                "JWT SecretKey must be at least 32 characters long");
        }

        options.SaveToken = true;

        options.RequireHttpsMetadata = false;

        options.TokenValidationParameters =
            new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,

                IssuerSigningKey =
                    new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(secretKey)
                    ),

                ValidateIssuer = true,
                ValidIssuer = issuer,

                ValidateAudience = true,
                ValidAudience = audience,

                ValidateLifetime = true,

                ClockSkew = TimeSpan.Zero,

                NameClaimType = ClaimTypes.Name,

                RoleClaimType = ClaimTypes.Role,

                RequireExpirationTime = true,

                RequireSignedTokens = true
            };

        // Read JWT From HttpOnly Cookie
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                var token =
                    context.Request.Cookies["accessToken"];

                if (!string.IsNullOrEmpty(token))
                {
                    context.Token = token;
                }

                return Task.CompletedTask;
            }
        };
    });
// Add Authorization
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"))
    .AddPolicy("UserOrAdmin", policy => policy.RequireRole("User", "Admin"));

builder.Services.AddAuthorization();

// Add CORS policies
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
            .AllowAnyMethod()
            .AllowAnyHeader().AllowCredentials();
    });

    options.AddPolicy("Production", policy =>
    {
        policy.WithOrigins("https://yourdomain.com", "https://www.yourdomain.com")
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials();
    });
});

builder.Services.AddMemoryCache();
builder.Services.AddResponseCompression();

var app = builder.Build();

// 2. Configure the HTTP request pipeline.

// Security headers middleware
app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    await next();
});

app.UseResponseCompression();

// Apply CORS based on Environment

//app.UseCors(app.Environment.IsDevelopment() ? "AllowAll" : "Production");
app.UseCors("AllowAll");


app.UseAuthentication();
app.UseAuthorization();


// Generate the OpenAPI JSON
app.MapOpenApi();

// Serve the Scalar UI
app.MapScalarApiReference(options =>
{
    options
        .WithTitle("My API Documentation")
        .WithTheme(ScalarTheme.BluePlanet)
        .WithDefaultHttpClient(ScalarTarget.CSharp, ScalarClient.HttpClient);
});
// --- DOCUMENTATION FIX END ---

app.MapControllers();

// Initialize database and seed roles
using (var scope = app.Services.CreateScope())
{
    try
    {
        var services = scope.ServiceProvider;
        var context = services.GetRequiredService<AppDbContext>();
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
        var userManager = services.GetRequiredService<UserManager<IdentityUser>>();

        await context.Database.MigrateAsync();

        string[] roles = { "Admin", "User", "Moderator" };
        foreach (var role in roles)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                await roleManager.CreateAsync(new IdentityRole(role));
            }
        }

        await SeedDefaultAdminUser(userManager, builder.Configuration);
        Console.WriteLine("Database initialization completed successfully.");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"An error occurred while initializing the database: {ex.Message}");
    }
}

app.Run();

// Helper method
static async Task SeedDefaultAdminUser(UserManager<IdentityUser> userManager, IConfiguration configuration)
{
    var adminEmail = configuration["DefaultAdmin:Email"] ?? "admin@example.com";
    var adminPassword = configuration["DefaultAdmin:Password"] ?? "Admin123!";

    var adminUser = await userManager.FindByEmailAsync(adminEmail);
    if (adminUser == null)
    {
        adminUser = new IdentityUser
        {
            UserName = adminEmail,
            Email = adminEmail,
            EmailConfirmed = true
        };

        var result = await userManager.CreateAsync(adminUser, adminPassword);
        if (result.Succeeded)
        {
            await userManager.AddToRoleAsync(adminUser, "Admin");

            var claims = new[]
            {
                new System.Security.Claims.Claim(CustomClaimTypes.FirstName, "Admin"),
                new System.Security.Claims.Claim(CustomClaimTypes.LastName, "User")
            };
            await userManager.AddClaimsAsync(adminUser, claims);

            Console.WriteLine($"Default admin user created: {adminEmail}");
        }
        else
        {
            Console.WriteLine(
                $"Failed to create admin user: {string.Join(", ", result.Errors.Select(e => e.Description))}");
        }
    }
}