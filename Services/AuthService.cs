using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using ShopSphere.DTOs;
using ShopSphere.Models;
using Microsoft.EntityFrameworkCore;

namespace ShopSphere.Services
{
	public class AuthService : IAuthService
	{
		private readonly UserManager<ApplicationUser> _userManager;
		private readonly SignInManager<ApplicationUser> _signInManager;
		private readonly JwtSettings _jwtSettings;
		private readonly RoleManager<IdentityRole> _roleManager;
		private readonly ILogger<AuthService> _logger;
		// Constructor injection for dependencies
		public AuthService(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager,
			IOptions<JwtSettings> jwtSettings, RoleManager<IdentityRole> roleManager, ILogger<AuthService> logger)
		{
			_userManager = userManager;
			_signInManager = signInManager;
			_jwtSettings = jwtSettings.Value;
			_roleManager = roleManager;
			_logger = logger;
		}

		public async Task<AuthResult> RegisterAsync(RegisterDto registerDto)
		{
			try
			{
				// Check if user already exists
				var existingUser = await _userManager.FindByEmailAsync(registerDto.Email);
				if (existingUser != null)
				{
					return new AuthResult
					{
						Success = false,
						Message = "User with this email already exists",
						Errors = new List<string> { "Email already registered" }
					};
				}
				// Create new user
				var newUser = new ApplicationUser
				{
					FirstName = registerDto.FirstName,
					LastName = registerDto.LastName,
					Email = registerDto.Email,
					UserName = registerDto.Email,
					CreatedAt = DateTime.UtcNow,
					IsActive = true
				};

				var result = await _userManager.CreateAsync(newUser, registerDto.Password);

				if (!result.Succeeded)
				{
					return new AuthResult
					{
						Success = false,
						Message = "Registration failed",
						Errors = result.Errors.Select(e => e.Description).ToList()
					};
				}

				// Assign default role
				await EnsureRolesExist();
				await _userManager.AddToRoleAsync(newUser, "Admin");

				// Generate token
				var token = await GenerateJwtTokenAsync(newUser);
				var refreshToken = GenerateRefreshToken();

				// Save refresh token
				newUser.RefreshToken = refreshToken;
				newUser.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationInDays);
				await _userManager.UpdateAsync(newUser);

				_logger.LogInformation($"User {newUser.Email} registered successfully");

				return new AuthResult
				{
					Success = true,
					Message = "User registered successfully",
					Data = new LoginResponseDto
					{
						Token = token,
						RefreshToken = refreshToken,
						Expiration = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationInMinutes),
						UserId = newUser.Id,
						Email = newUser.Email!,
						Username = newUser.UserName!,
						Roles = new List<string> { "User" }
					}
				};
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Error during registration");
				return new AuthResult
				{
					Success = false,
					Message = "An error occurred during registration",
					Errors = new List<string> { ex.Message }
				};
			}
		}

		// Login Service
		public async Task<AuthResult> LoginAsync(LoginDto loginDto)
		{
			try
			{
				// Find user by email or username
				var user = await _userManager.FindByEmailAsync(loginDto.EmailOrUsername);
				if (user == null)
				{
					user = await _userManager.FindByNameAsync(loginDto.EmailOrUsername);
				}

				if (user == null)
				{
					return new AuthResult
					{
						Success = false,
						Message = "Invalid credentials",
						Errors = new List<string> { "User not found" }
					};
				}

				if (!user.IsActive)
				{
					return new AuthResult
					{
						Success = false,
						Message = "Account is deactivated",
						Errors = new List<string> { "Account is not active" }
					};
				}

				// Check password
				var result = await _signInManager.CheckPasswordSignInAsync(user, loginDto.Password, false);

				if (!result.Succeeded)
				{
					return new AuthResult
					{
						Success = false,
						Message = "Invalid credentials",
						Errors = new List<string> { "Invalid password" }
					};
				}

				// Update last login
				user.LastLoginAt = DateTime.UtcNow;
				await _userManager.UpdateAsync(user);

				// Generate tokens
				var token = await GenerateJwtTokenAsync(user);
				var refreshToken = GenerateRefreshToken();

				// Save refresh token
				user.RefreshToken = refreshToken;
				user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationInDays);
				await _userManager.UpdateAsync(user);

				// Get user roles
				var roles = await _userManager.GetRolesAsync(user);

				_logger.LogInformation($"User {user.Email} logged in successfully");

				return new AuthResult
				{
					Success = true,
					Message = "Login successful",
					Data = new LoginResponseDto
					{
						Token = token,
						RefreshToken = refreshToken,
						Expiration = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationInMinutes),
						UserId = user.Id,
						Email = user.Email!,
						Username = user.UserName!,
						Roles = roles.ToList()
					}
				};
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Error during login");
				return new AuthResult
				{
					Success = false,
					Message = "An error occurred during login",
					Errors = new List<string> { ex.Message }
				};
			}
		}

		// Generate secure JWT token
		private async Task<string> GenerateJwtTokenAsync(ApplicationUser user)
		{
			var tokenHandler = new JwtSecurityTokenHandler();
			var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret);

			var claims = new List<Claim>
			{
				new Claim(JwtRegisteredClaimNames.Sub, user.Id),
				new Claim(JwtRegisteredClaimNames.Email, user.Email!),
				new Claim(JwtRegisteredClaimNames.Name, user.UserName!),
				new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
				new Claim("firstName", user.FirstName),
				new Claim("lastName", user.LastName)
			};

			// Add roles
			var roles = await _userManager.GetRolesAsync(user);
			claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

			var tokenDescriptor = new SecurityTokenDescriptor
			{
				Subject = new ClaimsIdentity(claims),
				Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationInMinutes),
				Issuer = _jwtSettings.Issuer,
				Audience = _jwtSettings.Audience,
				SigningCredentials = new SigningCredentials(
					new SymmetricSecurityKey(key),
					SecurityAlgorithms.HmacSha256Signature)
			};

			var token = tokenHandler.CreateToken(tokenDescriptor);
			return tokenHandler.WriteToken(token);
		}

		// Generate secure refresh token
		private string GenerateRefreshToken()
		{
			var randomNumber = new byte[32];
			using var rng = RandomNumberGenerator.Create();
			rng.GetBytes(randomNumber);
			return Convert.ToBase64String(randomNumber);
		}

		// Add roles to database
		private async Task EnsureRolesExist()
		{
			string[] roles = { "Admin", "User", "Manager" };

			foreach (var role in roles)
			{
				if (!await _roleManager.RoleExistsAsync(role))
				{
					await _roleManager.CreateAsync(new IdentityRole(role));
				}
			}
		}

	}
}
