using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using TweetBook.Contracts.v1;
using TweetBook.Controllers.v1.Requests;
using TweetBook.Controllers.v1.Responses;
using TweetBook.Services;
using TweetBook.Domain;
using System.Linq;

namespace TweetBook.Controllers.v1
{
    public class IdentityController : Controller
    {
        private readonly IIdentityService _identityService;

        public IdentityController(IIdentityService identityService)
        { 
            _identityService = identityService;
        }

        [HttpPost(ApiRoutes.Identity.Register)]
        public async Task<IActionResult> RegisterAsync([FromBody] UserRegistrationRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(new AuthFailedResponse
                {
                    Errors = ModelState.Values.SelectMany(x => x.Errors.Select(xx => xx.ErrorMessage))
                });

            AuthenticationResult authResponse = await _identityService.RegisterAsync(request.Email, request.Password);

            if (!authResponse.Success) return BadRequest(new AuthFailedResponse { Errors = authResponse.Errors });

            return Ok(new AuthSuccessResponse
            {
                Token = authResponse.Token,
                RefreshToken = authResponse.RefreshToken
            });
        }

        [HttpPost(ApiRoutes.Identity.Login)]
        public async Task<IActionResult> LoginAsync([FromBody] UserLoginRequest request)
        {
            AuthenticationResult authResponse = await _identityService.LoginAsync(request.Email, request.Password);

            if (!authResponse.Success) return BadRequest(new AuthFailedResponse { Errors = authResponse.Errors });

            return Ok(new AuthSuccessResponse {
                Token = authResponse.Token,
                RefreshToken = authResponse.RefreshToken
            });
        }

        [HttpPost(ApiRoutes.Identity.Refresh)]
        public async Task<IActionResult> RefreshAsync([FromBody] RefreshTokenRequest request)
        {
            AuthenticationResult authResponse = await _identityService.RefreshTokenAsync(request.Token, request.RefreshToken);

            if (!authResponse.Success) return BadRequest(new AuthFailedResponse { Errors = authResponse.Errors });

            return Ok(new AuthSuccessResponse
            {
                Token = authResponse.Token,
                RefreshToken = authResponse.RefreshToken
            });
        }
    }
}
