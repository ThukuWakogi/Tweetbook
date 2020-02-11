using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using TweetBook.Data;
using TweetBook.Domain;
using TweetBook.Options;

namespace TweetBook.Services
{
    public class IdentityService : IIdentityService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JwtSettings _jwtSettings;
        private readonly TokenValidationParameters _tokenValidationParameters;
        private readonly DataContext _context;

        public IdentityService(UserManager<IdentityUser> userManager,
                               JwtSettings jwtSettings,
                               TokenValidationParameters tokenValidationParameters,
                               DataContext dataContext)
        {
            _userManager = userManager;
            _jwtSettings = jwtSettings;
            _tokenValidationParameters = tokenValidationParameters;
            _context = dataContext;
        }

        public async Task<AuthenticationResult> LoginAsync(string email, string password)
        {
            IdentityUser user = await _userManager.FindByEmailAsync(email);

            if (user == null)
                return new AuthenticationResult
                {
                    Errors = new[] { "user does not exist" }
                };

            bool userHasValidPassword = await _userManager.CheckPasswordAsync(user, password);

            if (!userHasValidPassword)
                return new AuthenticationResult
                {
                    Errors = new[] { "user password is invalid" }
                };

            return await GenerateAuthenticationResultForUserAsync(user);
        }

        public async Task<AuthenticationResult> RefreshTokenAsync(string token, string refreshToken)
        {
            ClaimsPrincipal validatedToken = GetPrincipalFromToken(token);

            if (validatedToken == null) return new AuthenticationResult { Errors = new[] { "Invalid Token" } };

            long expiryDateUnix = long.Parse(validatedToken.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Exp).Value);
            DateTime expiryDateTimeUTC = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                .AddSeconds(expiryDateUnix);

            if (expiryDateTimeUTC > DateTime.UtcNow) return new AuthenticationResult { Errors = new[] { "This token hasn't expired yet" } };

            string jti = validatedToken.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Jti).Value;
            RefreshToken storedRefreshedToken = await _context.RefreshTokens.SingleOrDefaultAsync(x => x.Token == refreshToken);

            if (storedRefreshedToken == null) return new AuthenticationResult { Errors = new[] { "This refresh token does not exist" } };

            if (DateTime.UtcNow > storedRefreshedToken.ExpiryDate) return new AuthenticationResult { Errors = new[] { "This refresh token has expired" } };

            if (storedRefreshedToken.Invalidated) return new AuthenticationResult { Errors = new[] { "This refresh token has been invalidated" } };

            if (storedRefreshedToken.Used) return new AuthenticationResult { Errors = new[] { "This refresh token has been used" } };

            if (storedRefreshedToken.JwtId != jti) return new AuthenticationResult { Errors = new[] { "This refresh token does not match this JWT" } };

            storedRefreshedToken.Used = true;
            _context.RefreshTokens.Update(storedRefreshedToken);
            await _context.SaveChangesAsync();
            var user = await _userManager.FindByIdAsync(validatedToken.Claims.Single(x => x.Type == "id").Value);

            return await GenerateAuthenticationResultForUserAsync(user);
        }

        private ClaimsPrincipal GetPrincipalFromToken(string token)
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            try
            {
                ClaimsPrincipal principal = tokenHandler.ValidateToken(
                    token, _tokenValidationParameters, out SecurityToken validatedToken);

                if (!IsJwtWithValidSecurityAlgorithm(validatedToken)) return null;

                return principal;
            }
            catch
            {
                return null;
            }
        }

        private bool IsJwtWithValidSecurityAlgorithm(SecurityToken validatedToken)
        {
            return (validatedToken is JwtSecurityToken jwtSecurityToken &&
                jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase));
        }

        public async Task<AuthenticationResult> RegisterAsync(string email, string password)
        {
            IdentityUser existingUser = await _userManager.FindByEmailAsync(email);

            if (existingUser != null)
            {
                Console.WriteLine(_userManager.FindByEmailAsync(email));
                return new AuthenticationResult
                {
                    Errors = new[] { "user with this email already exists" }
                };
            }

            IdentityUser newUser = new IdentityUser
            {
                Id = Guid.NewGuid().ToString(),
                Email = email,
                UserName = email,
            };
            IdentityResult createdUser = await _userManager.CreateAsync(newUser, password);

            if (!createdUser.Succeeded)
                return new AuthenticationResult
                {
                    Errors = createdUser.Errors.Select(x => x.Description)
                };

            return await GenerateAuthenticationResultForUserAsync(newUser);
        }

        private async Task<AuthenticationResult> GenerateAuthenticationResultForUserAsync(IdentityUser user)
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim("id", user.Id),
                }),
                Expires = DateTime.UtcNow.AddSeconds(45),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_jwtSettings.Secret)),
                    SecurityAlgorithms.HmacSha256Signature
                ),
            };
            SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
            RefreshToken refreshToken = new RefreshToken
            {
                JwtId = token.Id,
                UserId = user.Id,
                CreationDate = DateTime.UtcNow,
                ExpiryDate = DateTime.UtcNow.AddMonths(6),
                Token = Guid.NewGuid().ToString()
            };
            await _context.RefreshTokens.AddAsync(refreshToken);
            await _context.SaveChangesAsync();

            return new AuthenticationResult()
            {
                Success = true,
                Token = tokenHandler.WriteToken(token),
                RefreshToken = refreshToken.Token
            };
        }
    }
}
