using System.Net.Mime;
using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using QRCoder;
using SimpleAuthentication;
using SimpleAuthentication.JwtBearer;
using TinyHelpers.AspNetCore.Extensions;
using TinyHelpers.AspNetCore.OpenApi;
using TwoFactorAuthenticationSample.DataAccessLayer;
using TwoFactorAuthenticationSample.DataAccessLayer.Entities;
using TwoFactorAuthenticationSample.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddSqlServer<ApplicationDbContext>(builder.Configuration.GetConnectionString("SqlConnection"));

builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
{
    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedEmail = true;
    options.Password.RequiredLength = 8;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireDigit = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

builder.Services.AddSimpleAuthentication(builder.Configuration);

builder.Services.AddDataProtection().SetApplicationName(builder.Environment.ApplicationName)
    .PersistKeysToDbContext<ApplicationDbContext>();

builder.Services.AddScoped(services =>
{
    var dataProtectionProvider = services.GetRequiredService<IDataProtectionProvider>();
    var dataProtector = dataProtectionProvider.CreateProtector(nameof(ITimeLimitedDataProtector)).ToTimeLimitedDataProtector();
    return dataProtector;
});

builder.Services.AddDefaultProblemDetails();
builder.Services.AddDefaultExceptionHandler();

builder.Services.AddOpenApi(options =>
{
    options.RemoveServerList();
    options.AddSimpleAuthentication(builder.Configuration);
});

var app = builder.Build();
await ConfigureDatabaseAsync(app.Services);

// Configure the HTTP request pipeline.
app.UseHttpsRedirection();

app.UseExceptionHandler();
app.UseStatusCodePages();

app.MapOpenApi().AllowAnonymous();
app.UseSwaggerUI(options =>
{
    options.SwaggerEndpoint("/openapi/v1.json", app.Environment.ApplicationName);
});

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

var identityApi = app.MapGroup("/api/auth");

identityApi.MapPost("/register", async Task<Results<Created, BadRequest<IEnumerable<IdentityError>>>> (RegisterRequest request, UserManager<ApplicationUser> userManager) =>
{
    var user = new ApplicationUser
    {
        FirstName = request.FirstName,
        LastName = request.LastName,
        UserName = request.Email.ToLowerInvariant(),
        Email = request.Email.ToLowerInvariant(),
        TwoFactorEnabled = true,
        EmailConfirmed = true
    };

    var result = await userManager.CreateAsync(user, request.Password);
    return result.Succeeded ? TypedResults.Created() : TypedResults.BadRequest(result.Errors);
});

identityApi.MapPost("/login", async Task<Results<Ok<LoginResponse>, BadRequest>> (LoginRequest request, SignInManager<ApplicationUser> signInManager, IJwtBearerService jwtBearerService,
    ITimeLimitedDataProtector dataProtector) =>
{
    var user = await signInManager.UserManager.FindByEmailAsync(request.Email);
    if (user is null)
    {
        return TypedResults.BadRequest();
    }

    var result = await signInManager.PasswordSignInAsync(request.Email, request.Password, false, false);
    if (!result.Succeeded && !result.RequiresTwoFactor)
    {
        return TypedResults.BadRequest();
    }

    var token = dataProtector.Protect(user.Id.ToString(), TimeSpan.FromMinutes(5));
    return TypedResults.Ok(new LoginResponse(token));
});

identityApi.MapGet("/qrcode", async Task<Results<FileContentHttpResult, BadRequest>> (string token, ITimeLimitedDataProtector dataProtector, UserManager<ApplicationUser> userManager, IWebHostEnvironment environment) =>
{
    ApplicationUser? user = null;
    try
    {
        var userId = dataProtector.Unprotect(token);
        user = await userManager.FindByIdAsync(userId);
    }
    catch
    {
        return TypedResults.BadRequest();
    }

    if (user is null || await userManager.GetAuthenticatorKeyAsync(user) is not null)
    {
        return TypedResults.BadRequest();
    }

    await userManager.ResetAuthenticatorKeyAsync(user);
    var secret = await userManager.GetAuthenticatorKeyAsync(user);

    var payload = new PayloadGenerator.OneTimePassword
    {
        Issuer = environment.ApplicationName,
        Secret = secret!,
        Label = user.Email
    };

    using var qrCodeData = QRCodeGenerator.GenerateQrCode(payload, QRCodeGenerator.ECCLevel.Q);
    using var qrCode = new PngByteQRCode(qrCodeData);

    var qrCodeBytes = qrCode.GetGraphic(3);
    return TypedResults.File(qrCodeBytes, MediaTypeNames.Image.Png);
});

identityApi.MapPost("/validate", async Task<Results<Ok<LoginResponse>, BadRequest>> (ValidationRequest request, ITimeLimitedDataProtector dataProtector, UserManager<ApplicationUser> userManager,
    IJwtBearerService jwtBearerService) =>
{
    ApplicationUser? user = null;
    try
    {
        var userId = dataProtector.Unprotect(request.Token);
        user = await userManager.FindByIdAsync(userId);
    }
    catch
    {
        return TypedResults.BadRequest();
    }

    if (user is null)
    {
        return TypedResults.BadRequest();
    }

    var isValidTotpCode = await userManager.VerifyTwoFactorTokenAsync(user, userManager.Options.Tokens.AuthenticatorTokenProvider, request.Code);

    // Example of verification using Otp.NET library:
    // https://github.com/kspearrin/Otp.NET
    //var secret = await userManager.GetAuthenticatorKeyAsync(user);
    //var totp = new Totp(Base32Encoding.ToBytes(secret));

    //var isValidTotpCode = totp.VerifyTotp(request.Code, out var timeStepUsed, VerificationWindow.RfcSpecifiedNetworkDelay);

    if (!isValidTotpCode)
    {
        return TypedResults.BadRequest();
    }

    var token = await jwtBearerService.CreateTokenAsync(user.Email!);
    return TypedResults.Ok(new LoginResponse(token));
});

app.MapGet("/api/me", (ClaimsPrincipal user) =>
{
    return TypedResults.Ok(new User(user.Identity!.Name!));
})
.RequireAuthorization();

app.Run();

static async Task ConfigureDatabaseAsync(IServiceProvider serviceProvider)
{
    await using var scope = serviceProvider.CreateAsyncScope();
    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

    await dbContext.Database.MigrateAsync();
}