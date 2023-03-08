namespace PersonalVideoService.Services.Identity.API.Controllers;

[Route("api/v1/[controller]")]
[ApiController]
public class UsersController : IdentityController
{
    public UsersController(UserManager<User> userManager, RoleManager<Role> roleManager, IConfiguration configuration) :
        base(userManager, roleManager, configuration)
    { }

    [HttpGet]
    [Authorize(AuthenticationSchemes = "Bearer", Policy = "users/items")]
    [Route("users")]
    public async Task<List<UserDto>> ItemsAsync(int companyId, int pageSize, int pageIndex)
    {
        if (pageSize <= 0 || pageIndex < 0)
            return new List<UserDto>();

        return await _userManager.Users
            .Where(user => !user.Deleted)
            .OrderBy(user => user.Id)
            .Skip(pageSize * pageIndex)
            .Take(pageSize)
            .ToListAsync();
    }

    [Authorize(AuthenticationSchemes = "Bearer", Policy = "users/get")]
    [HttpGet]
    [Route("get")]
    public async Task<ActionResult<User>> GetAsync(string id)
    {
        if (string.IsNullOrWhiteSpace(id))
            return NotFound();

        var role = await _userManager.Users.FirstOrDefaultAsync(user => user.Id == id);
        return role == null ? NotFound() : Ok(role);
    }

    [Authorize(AuthenticationSchemes = "Bearer", Policy = "users/getByRole")]
    [HttpGet]
    [Route("getByRole")]
    public async Task<List<User>> GetByRoleAsync(int pageSize, int pageIndex, string roleId)
    {
        if (pageSize <= 0 || pageIndex < 0 || string.IsNullOrWhiteSpace(roleId))
            return new List<User>();

        Role role = (await _roleManager.Roles.FirstOrDefaultAsync(role => role.Id == roleId))!;
        if (role == null)
            return new List<User>();

        return await _userManager.Users
            .OrderBy(user => user.Id)
            .Where(user => _userManager.GetRolesAsync(user).Result.Contains(role.Name))
            .Skip(pageSize * pageIndex)
            .Take(pageSize)
            .ToListAsync();
    }

    [Authorize(AuthenticationSchemes = "Bearer", Policy = "users/find")]
    [HttpGet]
    [Route("find")]
    public async Task<List<User>> FindAsync(int pageSize, int pageIndex, string pattern)
    {
        if (pageSize <= 0 || pageIndex < 0 || string.IsNullOrWhiteSpace(pattern))
            return new List<User>();

        pattern = pattern.Trim().ToUpper();

        return await _userManager.Users
            .OrderBy(user => user.Id)
            .Where(user => user.ToString().ToUpper().Contains(pattern))
            .Skip(pageSize * pageIndex)
            .Take(pageSize)
            .ToListAsync();
    }
}