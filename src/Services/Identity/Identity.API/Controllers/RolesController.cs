namespace PersonalVideoService.Services.Identity.API.Controllers;

[Route("api/v1/[controller]")]
[ApiController]
public class RolesController : IdentityController
{
    public RolesController(UserManager<User> userManager, RoleManager<Role> roleManager, IConfiguration configuration) :
        base(userManager, roleManager, configuration)
    { }

    [Authorize(AuthenticationSchemes = "Bearer", Policy = "roles/create")]
    [HttpPost]
    [Route("add")]
    public async Task<IActionResult> CreateAsync(string name, int accessLevel)
    {
        if (string.IsNullOrWhiteSpace(name))
            return BadRequest();

        int userAccessLevel = await GetCurrentUserAccessLevelAsync();

        if (accessLevel <= 0)
            return BadRequest();

        if (accessLevel >= userAccessLevel)
            return Forbid();

        IdentityResult result = await _roleManager.CreateAsync(new Role(name.Trim(), accessLevel));

        if (!result.Succeeded)
            return BadRequest(result.Errors);

        return Ok();
    }

    [HttpGet]
    [Authorize(AuthenticationSchemes = "Bearer", Policy = "roles/items")]
    [Route("items")]
    public async Task<List<Role>> ItemsAsync(int pageSize, int pageIndex)
    {
        if (pageSize <= 0 || pageIndex < 0)
            return new List<Role>();

        return await _roleManager.Roles
            .OrderBy(role => role.Id)
            .Skip(pageSize * pageIndex)
            .Take(pageSize)
            .ToListAsync();
    }

    [Authorize(AuthenticationSchemes = "Bearer", Policy = "roles/get")]
    [HttpGet]
    [Route("get")]
    public async Task<ActionResult<Role>> GetAsync(string id)
    {
        if (string.IsNullOrWhiteSpace(id))
            return NotFound();

        var role = await _roleManager.Roles.FirstOrDefaultAsync(role => role.Id == id);
        return role == null ? NotFound() : Ok(role);
    }

    [Authorize(AuthenticationSchemes = "Bearer", Policy = "roles/find")]
    [HttpGet]
    [Route("find")]
    public async Task<List<Role>> FindAsync(int pageSize, int pageIndex, string pattern)
    {
        if (pageSize <= 0 || pageIndex < 0 || string.IsNullOrWhiteSpace(pattern))
            return new List<Role>();

        pattern = pattern.Trim().ToUpper();

        return await _roleManager.Roles
            .OrderBy(role => role.Id)
            .Where(role => role.NormalizedName.Contains(pattern))
            .Skip(pageSize * pageIndex)
            .Take(pageSize)
            .ToListAsync();
    }

    [Authorize(AuthenticationSchemes = "Bearer", Policy = "roles/getInRange")]
    [HttpGet]
    [Route("getInRange")]
    public async Task<List<Role>> GetInRangeAsync(int pageSize, int pageIndex, int minAccessLevel, int maxAccessLevel)
    {
        if (pageSize <= 0 || pageIndex < 0)
            return new List<Role>();

        return await _roleManager.Roles
            .OrderBy(role => role.Id)
            .Where(role => role.AccessLevel >= minAccessLevel && role.AccessLevel <= maxAccessLevel)
            .Skip(pageSize * pageIndex)
            .Take(pageSize)
            .ToListAsync();
    }

    [Authorize(AuthenticationSchemes = "Bearer", Policy = "roles/change")]
    [HttpPut]
    [Route("change")]
    public async Task<ActionResult> ChangeAsync(RoleDto role)
    {
        if (string.IsNullOrWhiteSpace(role.Id) || string.IsNullOrWhiteSpace(role.Name) || role.AccessLevel < 1)
            return BadRequest();

        int accessLevel = await GetCurrentUserAccessLevelAsync();

        Role roleEntity = (await _roleManager.Roles.FirstOrDefaultAsync(r => r.Id == role.Id))!;

        if (roleEntity == null)
            return NotFound();

        int max = await GetAccessLevelMaxAsync();
        IdentityResult result;

        if (roleEntity.AccessLevel >= accessLevel)
        {
            if (accessLevel == max)
            {
                if (roleEntity.AccessLevel == max)
                {
                    var secondRole = await _roleManager.Roles
                        .OrderByDescending(role => role.AccessLevel)
                        .Skip(1)
                        .FirstOrDefaultAsync();

                    int secondMax = secondRole == null ? 0 : secondRole.AccessLevel;

                    if (role.AccessLevel <= secondMax)
                        return BadRequest();
                }
                else if (role.AccessLevel >= max || role.AccessLevel < 1)
                    return BadRequest();

                roleEntity.Name = role.Name;
                roleEntity.AccessLevel = role.AccessLevel;

                result = await _roleManager.UpdateAsync(roleEntity);

                return result.Succeeded ? Ok() : BadRequest(result.Errors);
            }
            else if (roleEntity.AccessLevel > accessLevel)
                return NotFound();

            var userRoles = await GetCurrentUserRolesAsync();

            return userRoles.Contains(role.Name) ? Forbid() : NotFound();

        }
        else if (role.AccessLevel >= accessLevel || role.AccessLevel < 1)
            return BadRequest();

        roleEntity.Name = role.Name;
        roleEntity.AccessLevel = role.AccessLevel;

        result = await _roleManager.UpdateAsync(roleEntity);

        return result.Succeeded ? Ok() : BadRequest(result.Errors);
    }

    [Authorize(AuthenticationSchemes = "Bearer", Policy = "roles/remove")]
    [HttpDelete]
    [Route("remove")]
    public async Task<ActionResult> RemoveAsync(string id)
    {
        if (string.IsNullOrWhiteSpace(id))
            return BadRequest();

        int accessLevel = await GetCurrentUserAccessLevelAsync();

        var role = await _roleManager.Roles.FirstOrDefaultAsync(role => role.Id == id);

        if (role == null)
            return NotFound();

        var max = await GetAccessLevelMaxAsync();

        if (role.AccessLevel == max)
            return accessLevel == max ? BadRequest() : NotFound();

        if (role.AccessLevel > accessLevel)
            return NotFound();

        if (role.AccessLevel == accessLevel)
        {
            var userRoles = await GetCurrentUserRolesAsync();
            return userRoles.Contains(role.Name) ? Forbid() : NotFound();
        }

        var result = await _roleManager.DeleteAsync(role);

        if (!result.Succeeded)
            return BadRequest(result.Errors);

        return Ok();
    }
}