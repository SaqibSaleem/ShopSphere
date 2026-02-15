using ShopSphere.DTOs;
using static ShopSphere.DTOs.AuthDTOs;

namespace ShopSphere.Services
{
	public class AuthenticationService
	{
	}
	public interface IAuthService
	{
		Task<AuthResult> RegisterAsync(RegisterDto registerDto);
		Task<AuthResult> LoginAsync(LoginDto loginDto);
		//Task<AuthResult> RefreshTokenAsync(string refreshToken);
		//Task<bool> LogoutAsync(string userId);
	}

	public class AuthResult
	{
		public bool Success { get; set; }
		public string Message { get; set; } = string.Empty;
		public LoginResponseDto? Data { get; set; }
		public List<string> Errors { get; set; } = new();
	}
}
