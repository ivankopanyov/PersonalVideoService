namespace PersonalVideoService.Services.Identity.API.Model;

public class Company
{
    [Key]
    public int Id { get; set; }

    public string Name { get; set; }

    public bool IsBase { get; set; } = false;

    public bool IsLockout { get; set; } = false;

    public bool IsDeleted { get; set; } = false;
}
