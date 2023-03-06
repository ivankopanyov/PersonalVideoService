namespace PersonalVideoService.Services.Identity.API.Infrastructure.Policies.Requirements;

public class AccessRequirement : IAuthorizationRequirement
{
    public string PolicyName { get; init; }

    public AccessRequirement(string policyName) => PolicyName = policyName;
}