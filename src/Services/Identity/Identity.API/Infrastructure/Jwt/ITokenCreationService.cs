namespace PersonalVideoService.Services.Identity.API.Infrastructure.Jwt;

public interface ITokenCreationService
{
    AuthenticateResponse CreateToken(User user);
}
