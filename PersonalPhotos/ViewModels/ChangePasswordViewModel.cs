using System.ComponentModel.DataAnnotations;

namespace PersonalPhotos.ViewModels
{
  public class ChangePasswordViewModel
  {
    [Required]
    public string EmailAddress { get; set; }
    [Required]
    public string Password { get; set; }
    [Required]
    public string Token { get; set; }
  }
}