using System.Threading.Tasks;
using Microsoft.AspNet.Identity;

namespace ASPNETIdentityWithOnion.Data.Identity
{
    public class SmsService : IIdentityMessageService
    {
        public Task SendAsync(IdentityMessage message)
        {
            // Plug in your sms service here to send a text message.
            return Task.FromResult(0);
        }
    }
}
