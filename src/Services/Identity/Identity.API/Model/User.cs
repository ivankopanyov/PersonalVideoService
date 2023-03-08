namespace PersonalVideoService.Services.Identity.API.Model;

public class User : IdentityUser<int>
{
    public string FirstName { get; set; }

    public string LastName { get; set; }

    public Role CurrentRole { get; set; }

    public bool Deleted { get; set; }
}
