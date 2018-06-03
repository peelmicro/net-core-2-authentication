using System.ComponentModel.DataAnnotations;

namespace PersonalPhotos.ViewModels
{
    public class MfaCreateViewModel
    {
        public string AuthKey { get; set; }
        public string FormattedAuthKey { get; set; }
        [Required(ErrorMessage = "You must enter a code for MFA!")]
        public string Code { get; set; }
    }
}