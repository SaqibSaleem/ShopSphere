using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using ShopSphere.Models;

namespace ShopSphere.Data
{
	public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
	{
		public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
			: base(options)
		{
		}
		protected override void OnModelCreating(ModelBuilder builder)
		{
			base.OnModelCreating(builder);

			// Optional: Configure additional relationships or constraints
			builder.Entity<ApplicationUser>(entity =>
			{
				entity.Property(e => e.FirstName).HasMaxLength(50);
				entity.Property(e => e.LastName).HasMaxLength(50);
			});
		}
	}
}
