using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace TestApiJWT.Models
{
    // Custom user class that extends IdentityUser to include additional properties
    public class ApplicationUser:IdentityUser
    {
        [Required, MaxLength(50)]
        public string FirstName { get; set; }

        [Required, MaxLength(50)]
        public string LastName { get; set; }
    }
}
