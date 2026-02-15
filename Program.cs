using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using ShopSphere.Data;
using ShopSphere.Models;
using ShopSphere.Services;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
//builder.Services.AddSwaggerGen(c =>
//{
//	c.SwaggerDoc("v1", new() { Title = "Auth API", Version = "v1" });

//	// Configure Swagger to use JWT
//	c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
//	{
//		Description = "JWT Authorization header using the Bearer scheme. Enter 'Bearer' [space] and then your token",
//		Name = "Authorization",
//		In = Microsoft.OpenApi.Models.ParameterLocation.Header,
//		Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
//		Scheme = "Bearer"
//	});

//	c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
//	{
//		{
//			new Microsoft.OpenApi.Models.OpenApiSecurityScheme
//			{
//				Reference = new Microsoft.OpenApi.Models.OpenApiReference
//				{
//					Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
//					Id = "Bearer"
//				}
//			},
//			new string[] {}
//		}
//	});
//});

// Configure Database
builder.Services.AddDbContext<ApplicationDbContext>(options =>
	options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Configure Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
	// Password settings
	options.Password.RequireDigit = true;
	options.Password.RequiredLength = 6;
	options.Password.RequireNonAlphanumeric = false;
	options.Password.RequireUppercase = true;
	options.Password.RequireLowercase = true;

	// Lockout settings
	options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
	options.Lockout.MaxFailedAccessAttempts = 5;
	options.Lockout.AllowedForNewUsers = true;

	// User settings
	options.User.RequireUniqueEmail = true;
	options.SignIn.RequireConfirmedEmail = false; // Set to true if email confirmation is required
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Configure JWT Settings
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
builder.Services.Configure<JwtSettings>(jwtSettings);

var key = Encoding.ASCII.GetBytes(jwtSettings["Secret"] ?? throw new InvalidOperationException("JWT Secret not configured"));

// Configure Authentication
builder.Services.AddAuthentication(options =>
{
	options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
	options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
	options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
	options.RequireHttpsMetadata = false; // Set to true in production
	options.SaveToken = true;
	options.TokenValidationParameters = new TokenValidationParameters
	{
		ValidateIssuerSigningKey = true,
		IssuerSigningKey = new SymmetricSecurityKey(key),
		ValidateIssuer = true,
		ValidIssuer = jwtSettings["Issuer"],
		ValidateAudience = true,
		ValidAudience = jwtSettings["Audience"],
		ValidateLifetime = true,
		ClockSkew = TimeSpan.Zero // Remove delay of token expiration
	};

	// Optional: Handle JWT in WebSockets or SignalR
	options.Events = new JwtBearerEvents
	{
		OnMessageReceived = context =>
		{
			var accessToken = context.Request.Query["access_token"];
			var path = context.HttpContext.Request.Path;

			if (!string.IsNullOrEmpty(accessToken) && path.StartsWithSegments("/hubs"))
			{
				context.Token = accessToken;
			}

			return Task.CompletedTask;
		}
	};
});

// Register services
builder.Services.AddScoped<IAuthService, AuthService>();

// Add CORS policy
builder.Services.AddCors(options =>
{
	options.AddPolicy("AllowAll", builder =>
	{
		builder.AllowAnyOrigin()
			   .AllowAnyMethod()
			   .AllowAnyHeader();
	});
});

var app = builder.Build();

// Configure the HTTP request pipeline.
//if (app.Environment.IsDevelopment())
//{
//	app.UseSwagger();
//	app.UseSwaggerUI();
//}

app.UseHttpsRedirection();

app.UseCors("AllowAll");

app.UseAuthentication(); // Important: Add this before Authorization
app.UseAuthorization();

app.MapControllers();

// Create database on startup (optional - for development)
using (var scope = app.Services.CreateScope())
{
	var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
	dbContext.Database.Migrate(); // This will create/update the database

	// Seed roles
	var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
	await SeedRolesAsync(roleManager);
}

app.Run();

async Task SeedRolesAsync(RoleManager<IdentityRole> roleManager)
{
	string[] roles = { "Admin", "User", "Manager" };

	foreach (var role in roles)
	{
		if (!await roleManager.RoleExistsAsync(role))
		{
			await roleManager.CreateAsync(new IdentityRole(role));
		}
	}
}