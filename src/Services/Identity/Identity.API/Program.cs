using PersonalVideoService.Services.Identity.API.Model;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Name = "Authorization",
        Description = "Bearer Authentication with JWT Token",
        Type = SecuritySchemeType.Http
    });
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Id = "Bearer",
                    Type = ReferenceType.SecurityScheme
                }
            },
            new List<string>()
        }
    });
});

builder.Services.AddEntityFrameworkSqlite().AddDbContext<IdentityContext>();
builder.Services
    .AddIdentity<User, Role>(options =>
    {
        options.SignIn.RequireConfirmedAccount = false;
        options.User.RequireUniqueEmail = true;
        options.Password.RequireDigit = false;
        options.Password.RequiredLength = 6;
        options.Password.RequireNonAlphanumeric = false;
        options.Password.RequireUppercase = false;
        options.Password.RequireLowercase = false;
    })
    .AddEntityFrameworkStores<IdentityContext>();

builder.Services.AddScoped<ITokenCreationService, JwtService>();

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidAudience = builder.Configuration["Jwt:Audience"],
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"])
            )
        };
    });

builder.Services.AddTransient<IAuthorizationHandler, AccessHandler>();

var policies = Assembly.GetExecutingAssembly().GetTypes()
    .Where(type => typeof(IdentityController).IsAssignableFrom(type))
    .SelectMany(type => type.GetMethods())
    .Where(method => method.IsDefined(typeof(AuthorizeAttribute)))
    .Select(method => ((AuthorizeAttribute)method.GetCustomAttributes().First(attr => attr.GetType() == typeof(AuthorizeAttribute))).Policy)
    .Where(policy => !string.IsNullOrEmpty(policy))
    .ToHashSet();

builder.Services.AddAuthorization(options =>
{
    foreach (var policy in policies)
        options.AddPolicy(policy!, p => p.Requirements.Add(new AccessRequirement(policy!)));
});

var app = builder.Build();

using (var client = new IdentityContext(app.Configuration))
{
    client.Database.EnsureDeleted();
    client.Database.EnsureCreated();

    await client.Policies
        .Where(policy => !policies.Contains(policy.Name))
        .ForEachAsync(policy => client.Policies.Remove(policy));

    foreach (var policy in policies)
        if (client.Policies.FirstOrDefault(p => p.Name == policy) == null)
            client.Policies.Add(new Policy()
            {
                Name = policy!
            });

    client.SaveChanges();

    Company baseCompany = client.Companies
        .FirstOrDefault(company => company.IsBase)!;

    if (baseCompany == null)
    {
        baseCompany = new Company()
        {
            Name = "BaseCompany",
            IsBase = true
        };

        await client.Companies.AddAsync(baseCompany);
        client.SaveChanges();
    }

    using (var scope = app.Services.CreateScope())
    {
        var roleManager = (RoleManager<Role>)scope.ServiceProvider.GetService(typeof(RoleManager<Role>))!;
        Role superAdminRole = roleManager.Roles.FirstOrDefault(role => role.Company == baseCompany && role.IsSuperAdmin)!;

        if (superAdminRole == null)
        {
            superAdminRole = new Role()
            {
                Name = "Superadmin",
                Company = baseCompany,
                IsSuperAdmin = true
            };
            await roleManager.CreateAsync(superAdminRole);
        }

        var userManager = (UserManager<User>)scope.ServiceProvider.GetService(typeof(UserManager<User>))!;
        string email = "superadmin@basecompany.com";
        User superAdmin = userManager.Users.FirstOrDefault(user => user.Email == email)!;
        if (superAdmin == null)
        {
            superAdmin = new User()
            {
                UserName = email,
                Email = email,
                CurrentRole = superAdminRole
            };

            await userManager.CreateAsync(superAdmin, email);
            await userManager.AddToRolesAsync(superAdmin, new[] { superAdminRole.Name });
        }

        string userRoleName = "Users";
        Role userRole = roleManager.Roles.FirstOrDefault(role => role.Company == baseCompany && role.Name == userRoleName)!;

        if (userRole == null)
            await roleManager.CreateAsync(new Role()
            {
                Name = userRoleName,
                Company = baseCompany
            });
    }
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.UseCors(x => x
        .AllowAnyOrigin()
        .AllowAnyMethod()
        .AllowAnyHeader());

app.Run();