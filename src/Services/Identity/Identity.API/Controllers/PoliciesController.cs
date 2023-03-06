namespace PersonalVideoService.Services.Identity.API.Controllers;

[Route("api/v1/[controller]")]
[ApiController]
public class PoliciesController : IdentityController
{
    private readonly IdentityContext _identityContext;

    public PoliciesController(UserManager<User> userManager, RoleManager<Role> roleManager, IConfiguration configuration, IdentityContext identityContext) : base(userManager, roleManager, configuration)
    {
        _identityContext = identityContext;
    }

    [Authorize(AuthenticationSchemes = "Bearer", Policy = "policies/items")]
    [HttpGet]
    [Route("items")]
    public async Task<List<Policy>> ItemsAsync(int pageSize, int pageIndex)
    {
        if (pageSize <= 0 || pageIndex < 0)
            return new List<Policy>();

        return await _identityContext.Policies
            .OrderBy(policy => policy.Id)
            .Skip(pageSize * pageIndex)
            .Take(pageSize)
            .ToListAsync();
    }

    [Authorize(AuthenticationSchemes = "Bearer", Policy = "policies/get")]
    [HttpGet]
    [Route("get")]
    public async Task<ActionResult<Policy>> GetAsync(int id)
    {
        var policy = await _identityContext.Policies.FirstOrDefaultAsync(policy => policy.Id == id);
        return policy == null ? NotFound() : Ok(policy);
    }

    [Authorize(AuthenticationSchemes = "Bearer", Policy = "policies/find")]
    [HttpGet]
    [Route("find")]
    public async Task<List<Policy>> FindAsync(int pageSize, int pageIndex, string pattern)
    {
        if (pageSize <= 0 || pageIndex < 0 || string.IsNullOrWhiteSpace(pattern))
            return new List<Policy>();

        pattern = pattern.Trim().ToUpper();

        return await _identityContext.Policies
            .OrderBy(policy => policy.Id)
            .Where(policy => policy.Name.ToUpper().Contains(pattern))
            .Skip(pageSize * pageIndex)
            .Take(pageSize)
            .ToListAsync();
    }

    [Authorize(AuthenticationSchemes = "Bearer", Policy = "policies/getInRange")]
    [HttpGet]
    [Route("getInRange")]
    public async Task<IEnumerable<Policy>> GetInRangeAsync(int pageSize, int pageIndex, int minAccessLevel, int maxAccessLevel)
    {
        if (pageSize <= 0 || pageIndex < 0)
            return new List<Policy>();

        return await _identityContext.Policies
            .OrderBy(policy => policy.Id)
            .Where(policy => policy.MinimumAccessLevel >= minAccessLevel && policy.MinimumAccessLevel <= maxAccessLevel)
            .Skip(pageSize * pageIndex)
            .Take(pageSize)
            .ToListAsync();
    }

    [Authorize(AuthenticationSchemes = "Bearer", Policy = "policies/change")]
    [HttpPut]
    [Route("change")]
    public async Task<ActionResult> ChangeAsync(PolicyDto policy)
    {
        if (policy.MinimumAccessLevel < 0)
            return BadRequest();

        int accessLevel = await GetCurrentUserAccessLevelAsync();

        Policy policyEntity = (await _identityContext.Policies.FirstOrDefaultAsync(p => p.Id == policy.Id))!;
        if (policyEntity == null)
            return NotFound();

        int max = await GetAccessLevelMaxAsync();
        if (accessLevel == max)
        {
            if (policy.MinimumAccessLevel > accessLevel)
                return BadRequest();
        }
        else if (policyEntity.MinimumAccessLevel > accessLevel)
            return NotFound();
        else if (policy.MinimumAccessLevel > accessLevel)
            return BadRequest();

        policyEntity.MinimumAccessLevel = policy.MinimumAccessLevel;
        _identityContext.Policies.Update(policyEntity);
        await _identityContext.SaveChangesAsync();
        return Ok();
    }
}