namespace PersonalVideoService.Services.Identity.API.Infrastructure.Policies.Handlers;

public class AccessHandler : AuthorizationHandler<AccessRequirement>
{
    private readonly IConfiguration _configuration;

    private readonly IdentityContext _context;

    private readonly UserManager<User> _userManager;

    private readonly RoleManager<Role> _roleManager;

    public AccessHandler(IConfiguration configuration, IdentityContext context, UserManager<User> userManager, RoleManager<Role> roleManager)
    {
        _configuration = configuration;
        _context = context;
        _userManager = userManager;
        _roleManager = roleManager;
    }

    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AccessRequirement requirement)
    {
        var idClaim = context.User.FindFirst(c => c.Type == ClaimTypes.NameIdentifier);
        if (idClaim == null)
            return Task.CompletedTask;

        var user = _userManager.Users.FirstOrDefault(user => user.Id == idClaim.Value);
        if (user == null)
            return Task.CompletedTask;

        var accessLevel = _userManager.GetRolesAsync(user).Result
            .Select(roleName => _roleManager.Roles.FirstOrDefault(role => role.Name == roleName))
            .Where(role => role != null)
            .Select(role => role!.AccessLevel)
            .Max();

        var policy = _context.Policies.FirstOrDefault(p => p.Name == requirement.PolicyName);
        if (policy == null)
        {
            int max = _roleManager.Roles
                .Select(role => role.AccessLevel)
                .Max();

            if (accessLevel == max)
                context.Succeed(requirement);

            return Task.CompletedTask;
        }

        if (accessLevel >= policy.MinimumAccessLevel)
            context.Succeed(requirement);

        return Task.CompletedTask;
    }
}