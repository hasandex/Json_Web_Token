using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace Json_Web_Token.Models
{
    public class ApplicationUser : IdentityUser
    {
        [MaxLength(50)]
        public string FirstName { get; set; }
        [MaxLength(50)]
        public string LastName { get; set; }
    }
}
