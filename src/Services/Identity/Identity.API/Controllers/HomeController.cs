namespace PersonalVideoService.Services.Identity.API.Controllers;

public class HomeController : Controller
{
    public IActionResult Index() => new RedirectResult("~/swagger");
}