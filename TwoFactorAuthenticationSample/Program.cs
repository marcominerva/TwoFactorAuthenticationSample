using System.Security.Claims;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using SimpleAuthentication;
using SimpleAuthentication.JwtBearer;
using TinyHelpers.AspNetCore.Extensions;
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

builder.Services.AddDefaultProblemDetails();
builder.Services.AddDefaultExceptionHandler();

builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(options =>
{
    options.AddSimpleAuthentication(builder.Configuration);
});

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseHttpsRedirection();

app.UseExceptionHandler();
app.UseStatusCodePages();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

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
        EmailConfirmed = true
    };

    var result = await userManager.CreateAsync(user, request.Password);
    return result.Succeeded ? TypedResults.Created() : TypedResults.BadRequest(result.Errors);
})
.WithOpenApi();

identityApi.MapPost("/login", async Task<Results<Ok<LoginResponse>, BadRequest>> (LoginRequest request, SignInManager<ApplicationUser> signInManager, IJwtBearerService jwtBearerService) =>
{
    var result = await signInManager.PasswordSignInAsync(request.Email, request.Password, false, false);
    if (!result.Succeeded)
    {
        return TypedResults.BadRequest();
    }

    var token = await jwtBearerService.CreateTokenAsync(request.Email);
    return TypedResults.Ok(new LoginResponse(token));
})
.WithOpenApi();

app.MapGet("/api/me", (ClaimsPrincipal user) =>
{
    return TypedResults.Ok(new
    {
        user.Identity!.Name
    });
})
.RequireAuthorization()
.WithOpenApi();

app.Run();
