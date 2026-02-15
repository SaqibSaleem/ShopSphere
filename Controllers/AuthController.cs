using Microsoft.AspNetCore.Mvc;
using ShopSphere.DTOs;
using ShopSphere.Services;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;


namespace ShopSphere.Controllers
{
	[Route("api/Auth")]
	[ApiController]
	public class AuthController : ControllerBase
	{
		private readonly IAuthService _authService;
		private readonly ILogger<AuthController> _logger;

		public AuthController(IAuthService authService, ILogger<AuthController> logger)
		{
			_authService = authService;
			_logger = logger;
		}
		// register endpoint
		[Route("Register")]
		[HttpPost]
		public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
		{
			if (!ModelState.IsValid)
			{
				return BadRequest(ModelState);
			}
			var result = await _authService.RegisterAsync(registerDto);
			if (!result.Success)
			{
				return BadRequest(new { message = result.Message, errors = result.Errors });
			}
			return Ok(new { message = result.Message, result.Data });
		}
		// Login endpoint
		[Route("Login")]
		[HttpPost]
		public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
		{
			if (!ModelState.IsValid)
			{
				return BadRequest(ModelState);
			}

			var result = await _authService.LoginAsync(loginDto);

			if (!result.Success)
			{
				return Unauthorized(new { result.Message, result.Errors });
			}

			return Ok(new { result.Message, result.Data });
		}

		// Logout endpoint
		[Route("Logout")]
		[HttpGet]
		[Authorize]
		public async Task<IActionResult> Logout()
		{
			var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

			if (string.IsNullOrEmpty(userId))
			{
				return BadRequest(new { Message = "User not found" });
			}

			var result = await _authService.LogoutAsync(userId);

			if (!result)
			{
				return BadRequest(new { Message = "Logout failed" });
			}

			return Ok(new { Message = "Logged out successfully" });
		}

		[Route("GetCurrentUser")]
		[HttpGet]
		[Authorize]
		public IActionResult GetCurrentUser()
		{
			var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
			var email = User.FindFirstValue(ClaimTypes.Email);
			var username = User.FindFirstValue(ClaimTypes.Name);
			var firstName = User.FindFirstValue("firstName");
			var lastName = User.FindFirstValue("lastName");
			var roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();

			return Ok(new
			{
				UserId = userId,
				Email = email,
				Username = username,
				FirstName = firstName,
				LastName = lastName,
				Roles = roles
			});
		}


	}
}
