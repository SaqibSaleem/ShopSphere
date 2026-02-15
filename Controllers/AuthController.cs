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
		
	}
}
