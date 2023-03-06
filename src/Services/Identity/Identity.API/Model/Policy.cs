namespace PersonalVideoService.Services.Identity.API.Model;

public class Policy
{
    [Key]
    public int Id { get; set; }

    public string Name { get; set; }

    public int MinimumAccessLevel { get; set; }
}