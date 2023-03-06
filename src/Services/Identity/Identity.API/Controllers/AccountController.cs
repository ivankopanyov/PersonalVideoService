namespace PersonalVideoService.Services.Identity.API.Controllers;

[Route("api/v1/[controller]")]
[ApiController]
public class AccountController : IdentityController
{
    private readonly SignInManager<User> _signInManager;
    private readonly ITokenCreationService _jwtService;

    public AccountController(UserManager<User> userManager, RoleManager<Role> roleManager, IConfiguration configuration,
        SignInManager<User> signInManager, ITokenCreationService jwtService) : base(userManager, roleManager, configuration)
    {
        _signInManager = signInManager;
        _jwtService = jwtService;
    }

    [HttpPost]
    [Route("register")]
    public async Task<IActionResult> Register(RegisterViewModel registerModel)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var user = new User()
        {
            UserName = registerModel.Email,
            Email = registerModel.Email
        };

        var result = await _userManager.CreateAsync(user, registerModel.Password);

        if (!result.Succeeded)
            return BadRequest(result.Errors);

        var token = _jwtService.CreateToken(user);

        return Ok(token);
    }

    [HttpPost]
    [Route("login")]
    public async Task<ActionResult<AuthenticateResponse>> SignIn(AuthenticateRequest request)
    {

        if (!ModelState.IsValid)
            return BadRequest();

        var user = await _userManager.FindByNameAsync(request.Email);

        if (user == null)
            return BadRequest();

        var isPasswordValid = await _userManager.CheckPasswordAsync(user, request.Password);

        if (!isPasswordValid)
            return BadRequest();

        var token = _jwtService.CreateToken(user);

        return Ok(token);
    }
}