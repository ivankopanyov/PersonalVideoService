namespace PersonalVideoService.Services.Identity.API.Infrastructure;

public class IdentityContext : IdentityDbContext<User, Role, string>
{
    private readonly IConfiguration _configuration;

    public DbSet<Policy> Policies { get; set; }

    public IdentityContext(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    protected override void OnConfiguring(DbContextOptionsBuilder options)
    {
        options.UseSqlite(_configuration.GetConnectionString("WebApiDatabase"));
    }
}