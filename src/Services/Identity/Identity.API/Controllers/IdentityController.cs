namespace PersonalVideoService.Services.Identity.API.Controllers;

public class IdentityController : ControllerBase
{
    protected readonly UserManager<User> _userManager;
    protected readonly RoleManager<Role> _roleManager;
    protected readonly IConfiguration _configuration;

    public IdentityController(UserManager<User> userManager, RoleManager<Role> roleManager, IConfiguration configuration)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _configuration = configuration;
    }

    protected async Task<User?> GetCurrentUserAsync()
    {
        var idClaim = User.FindFirst(c => c.Type == ClaimTypes.NameIdentifier);

        if (idClaim == null)
            return null;

        return await _userManager.Users.FirstOrDefaultAsync(user => user.Id == idClaim.Value);
    }

    protected async Task<HashSet<string>> GetCurrentUserRolesAsync()
    {
        var user = await GetCurrentUserAsync();
        if (user == null)
            return new HashSet<string>();

        return (await _userManager.GetRolesAsync(user)).ToHashSet();
    }

    protected async Task<int> GetCurrentUserAccessLevelAsync()
    {
        HashSet<string> rolesNames = await GetCurrentUserRolesAsync();

        if (rolesNames.Count == 0)
            return 0;

        var role = await _roleManager.Roles
            .Where(role => rolesNames.Contains(role.Name))
            .OrderByDescending(role => role.AccessLevel)
            .FirstAsync();

        return role == null ? 0 : role.AccessLevel;
    }

    protected async Task<int> GetAccessLevelMinAsync()
    {
        var role = await _roleManager.Roles
            .OrderBy(role => role.AccessLevel)
            .FirstOrDefaultAsync();

        return role == null ? 0 : role.AccessLevel;
    }

    protected async Task<int> GetAccessLevelMaxAsync()
    {
        var role = await _roleManager.Roles
            .OrderByDescending(role => role.AccessLevel)
            .FirstOrDefaultAsync();

        return role == null ? 0 : role.AccessLevel;
    }
}
