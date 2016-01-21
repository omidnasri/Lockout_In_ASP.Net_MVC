using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(UserLockouts.Startup))]
namespace UserLockouts
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
