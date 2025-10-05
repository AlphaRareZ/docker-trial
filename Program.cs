using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using AuthenticationService;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllers();

// Add Identity Auth Service (includes DbContext and Identity setup)
builder.Services.AddIdentityAuthService(builder.Configuration);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Configure JWT Authentication
builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        var secretKey = builder.Configuration["JwtSettings:SecretKey"];
        var issuer = builder.Configuration["JwtSettings:Issuer"];
        var audience = builder.Configuration["JwtSettings:Audience"];

        if (string.IsNullOrEmpty(secretKey) || secretKey.Length < 32)
        {
            throw new InvalidOperationException("JWT SecretKey must be at least 32 characters long");
        }

        options.SaveToken = true;
        options.RequireHttpsMetadata = false;

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,

            // Critical: These settings handle claim mapping correctly
            NameClaimType = ClaimTypes.Name,
            RoleClaimType = ClaimTypes.Role,

            // For .NET 7 compatibility
            RequireExpirationTime = true,
            RequireSignedTokens = true
        };

        /*// Add detailed error handling
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                Console.WriteLine($"Authentication failed: {context.Exception.Message}");
                Console.WriteLine($"Exception type: {context.Exception.GetType().Name}");
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                Console.WriteLine("Token successfully validated");
                foreach (var claim in context.Principal.Claims)
                {
                    Console.WriteLine($"Claim: {claim.Type} = {claim.Value}");
                }
                return Task.CompletedTask;
            }
        };*/
    });

// Add Authorization
builder.Services.AddAuthorizationBuilder()
    // Add Authorization
    .AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"))
    // Add Authorization
    .AddPolicy("UserOrAdmin", policy => policy.RequireRole("User", "Admin"));

builder.Services.AddAuthorization();
// Add API Explorer services for Swagger
builder.Services.AddEndpointsApiExplorer();

// Add Swagger with JWT support

// Add CORS if needed
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
            .AllowAnyMethod()
            .AllowAnyHeader();
    });

    // More restrictive CORS policy for production
    options.AddPolicy("Production", policy =>
    {
        policy.WithOrigins("https://yourdomain.com", "https://www.yourdomain.com")
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials();
    });
});


// Add memory cache
builder.Services.AddMemoryCache();

// Add response compression
builder.Services.AddResponseCompression();

var app = builder.Build();

// 👇 Enable Swagger only in Development (recommended)
// if (app.Environment.IsDevelopment())
// {
    app.UseSwagger();
    app.UseSwaggerUI();
// }

// Security headers middleware
app.Use(async (context, next) =>
{
    context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Add("X-Frame-Options", "DENY");
    context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");
    await next();
});

//app.UseHttpsRedirection();
app.UseResponseCompression();

// Use CORS
if (app.Environment.IsDevelopment())
{
    app.UseCors("AllowAll");
}
else
{
    app.UseCors("Production");
}

app.UseAuthentication(); // Must come before UseAuthorization
app.UseAuthorization();

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

        // Apply any pending migrations
        await context.Database.MigrateAsync();

        // Ensure roles exist
        string[] roles = { "Admin", "User", "Moderator" };
        foreach (var role in roles)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                await roleManager.CreateAsync(new IdentityRole(role));
            }
        }

        // Create default admin user if it doesn't exist
        await SeedDefaultAdminUser(userManager, builder.Configuration);

        Console.WriteLine("Database initialization completed successfully.");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"An error occurred while initializing the database: {ex.Message}");
        // In production, you might want to log this properly
    }
}

app.Run();

// Helper method to seed default admin user
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

            // Add custom claims for admin
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