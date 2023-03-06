namespace PersonalVideoService.Services.Identity.API.Model;

public class Role : IdentityRole
{
    public int AccessLevel { get; set; }

    public Role() : base() { }

    public Role(string roleName, int rank) : base(roleName) => AccessLevel = rank;
}