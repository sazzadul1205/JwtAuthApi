using JwtAuthApi.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

// Register JwtService so controllers can use it
builder.Services.AddScoped<JwtService>();

//builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
//    .AddJwtBearer(options =>
//    {
//        options.TokenValidationParameters = new TokenValidationParameters
//        {
//            ValidateIssuer = false,             // temporarily skips checking who issued the token.
//            ValidateAudience = false,           // temporarily skips checking who the token is intended for.
//            ValidateLifetime = true,            // checks whether the token has expired.
//            ValidateIssuerSigningKey = true,    // checks the token's signature.
//            IssuerSigningKey = new SymmetricSecurityKey(  //provides the signing key used to validate tokens.
//                Encoding.UTF8.GetBytes("THIS_IS_A_TEMPORARY_SECRET_KEY_123456789")
//                )
//        };
//    });

// Load JWT settings from appsettings.json and User Secrets
var jwtSettings = builder.Configuration.GetSection("Jwt");

// Read the secret key; stop the application if it is missing
var secretKey = jwtSettings["SecretKey"] ?? throw new InvalidOperationException("Jwt:SecretKey is not configured.");

// Convert the secret key into the format JWT uses to verify token signatures
var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

// Configure the API to authenticate requests using JWT Bearer tokens
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            // Check that the token was issued by our expected issuer
            ValidateIssuer = true,
            ValidIssuer = jwtSettings["Issuer"],

            // Check that the token is intended for our expected audience
            ValidateAudience = true,
            ValidAudience = jwtSettings["Audience"],

            // Reject tokens that have expired
            ValidateLifetime = true,

            // Check that the token's signature is valid
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = signingKey,

            // Do not allow extra time after a token expires
            ClockSkew = TimeSpan.Zero
        };
    });

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
