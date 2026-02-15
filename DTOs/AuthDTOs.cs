using System.ComponentModel.DataAnnotations;

namespace ShopSphere.DTOs
{
	public class AuthDTOs
	{
		
	}
	public class RegisterDto
	{
		[Required(ErrorMessage = "First name is required")]
		[StringLength(50, MinimumLength = 2, ErrorMessage = "First name must be between 2 and 50 characters")]
		public string FirstName { get; set; } = string.Empty;

		[Required(ErrorMessage = "Last name is required")]
		[StringLength(50, MinimumLength = 2, ErrorMessage = "Last name must be between 2 and 50 characters")]
		public string LastName { get; set; } = string.Empty;

		[Required(ErrorMessage = "Email is required")]
		[EmailAddress(ErrorMessage = "Invalid email format")]
		public string Email { get; set; } = string.Empty;

		[Required(ErrorMessage = "Password is required")]
		[StringLength(100, MinimumLength = 6, ErrorMessage = "Password must be at least 6 characters")]
		[DataType(DataType.Password)]
		public string Password { get; set; } = string.Empty;

		[Compare("Password", ErrorMessage = "Passwords do not match")]
		[DataType(DataType.Password)]
		public string ConfirmPassword { get; set; } = string.Empty;
	}
	// Login Request DTO
	public class LoginDto
	{
		[Required(ErrorMessage = "Email is required")]
		public string EmailOrUsername { get; set; } = string.Empty;

		[Required(ErrorMessage = "Password is required")]
		[DataType(DataType.Password)]
		public string Password { get; set; } = string.Empty;
	}

	// Login Response DTO
	public class LoginResponseDto
	{
		public string Token { get; set; } = string.Empty;
		public string RefreshToken { get; set; } = string.Empty;
		public DateTime Expiration { get; set; }
		public string UserId { get; set; } = string.Empty;
		public string Email { get; set; } = string.Empty;
		public string Username { get; set; } = string.Empty;
		public List<string> Roles { get; set; } = new();
	}

	// Refresh Token Request DTO
	public class RefreshTokenDto
	{
		[Required]
		public string RefreshToken { get; set; } = string.Empty;
	}
}
