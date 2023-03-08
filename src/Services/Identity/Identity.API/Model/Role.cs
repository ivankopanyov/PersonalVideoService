namespace PersonalVideoService.Services.Identity.API.Model;

public class Role : IdentityRole
{
    public Company Company { get; set; }

    public HashSet<Policy> Policies { get; set; }

    public bool IsSuperAdmin { get; set; } = false;
}