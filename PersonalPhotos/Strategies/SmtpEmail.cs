using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using PersonalPhotos.Interfaces;
using PersonalPhotos.Models;

namespace PersonalPhotos.Strategies
{
  public class SmtpEmail : IEmail
  {
    private readonly EmailOptions _options;
    public SmtpEmail(IOptions<EmailOptions> options)
    {
      _options = options.Value;
    }
    public async Task Send(string emailAddress, string body, string subject)
    {
      var client = new SmtpClient
      {
        Host = _options.Host,
        Credentials = new NetworkCredential(_options.UserName, _options.Password)
      };

      var message = new MailMessage("juanp_perez@msn.com", emailAddress)
      {
        Body = body,
        Subject = subject,
        IsBodyHtml = true
      };

      await client.SendMailAsync(message);
    }
  }
}
