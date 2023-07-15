using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using WebApplication1.Context;
using WebApplication1.Helpers;
using WebApplication1.Models;
using System;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using WebApplication1.Models.TokenDbo;
using Microsoft.AspNetCore.Authentication;
using System.Data;

namespace WebApplication1.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;

        public UserController(AppDbContext authContext)
        {
            _authContext = authContext;
        }

        [HttpPost("authenticate")]

        public async Task<IActionResult> Authenticate([FromBody] User userobj)
        {   
            if(userobj == null)
                return BadRequest();

                var user = await _authContext.Users.
                FirstOrDefaultAsync(x=>x.Username == userobj.Username);

            if(user == null)
                return NotFound(new {Message = "User not Found! "});

            if (!PasswordHasher.VerifyPassword(userobj.Password, user.Password))
            {
                return BadRequest(new { Message = "Password is incorrect" });
            }

            user.Token = CreateJWT(user);
            var newAccessToken = user.Token;
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(5);
            await _authContext.SaveChangesAsync();

            return Ok(new TokenAPIDbo()
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            });
            
        }

        [HttpPost("register")]

        public async Task<IActionResult> RegisterUser([FromBody] User userobj)
        {
            if( userobj == null)
                return BadRequest();
            //Check Username
            if (await CheckUserNameExistAsync(userobj.Username))
                return BadRequest(new { Message = "Username Already Exist!" });


            //Check Email

            if (await CheckEmailExistAsync(userobj.Email))
                return BadRequest(new { Message = "Email Already Exist!" });


            //Check Password Strength

            var pass = CheckPasswordStreng(userobj.Password);
            if (!string.IsNullOrEmpty(pass))
                return BadRequest(new { Message = pass.ToString() });

            userobj.Password = PasswordHasher.HashPassword(userobj.Password);
            userobj.Role = "User";
            userobj.Token = "";

            await _authContext.Users.AddAsync(userobj);
            await _authContext.SaveChangesAsync();

            return Ok(new { Message = "User Registered!" });
        }
        [HttpPatch("setadmin/{userId}")]
        [Authorize(Roles = "SuperAdmin")]

        public async Task<IActionResult> SetUserAsAdmin([FromRoute] long userId)
        {
            var user = await _authContext.Users.FirstOrDefaultAsync(u => u.Id == userId);
            user.Role = "Admin";
            _authContext.Update(user);
            await _authContext.SaveChangesAsync();
            return Ok(new { Message = "User is set to Admin" });
        }

        private async Task<bool> CheckUserNameExistAsync(string username)
        {
            return await _authContext.Users.AnyAsync(x => x.Username == username);
        }

        private async Task<bool> CheckEmailExistAsync(string email)
        {
            return await _authContext.Users.AnyAsync(x => x.Email == email);
        }

        private string CheckPasswordStreng(string password)
        {
            StringBuilder sb = new StringBuilder();

            if(password.Length <8)
             sb.Append("Minimum password length should have at least 8 letters"+Environment.NewLine);

            if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]")
                && Regex.IsMatch(password, "[0-9]"))) 
            sb.Append("Password should be Alphanumeric"+ Environment.NewLine);

            if (!Regex.IsMatch(password, "[<,>,@,!,#,$,%,^,&,*,(,),_,+,\\[,\\],{,},?,:,;,|,',\\,.,/,~,`,-,=]"))
                sb.Append("Password should contain special character"+Environment.NewLine);
            return sb.ToString();
            
        }

        private string CreateJWT(User user)
        {
            var jwtTokenHeadler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("veryverysecret...");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name, $"{user.Username}")
            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddSeconds(10),
                SigningCredentials = credentials
            };
            var token = jwtTokenHeadler.CreateToken(tokenDescriptor);

            return jwtTokenHeadler.WriteToken(token);
        }

        private string CreateRefreshToken()
        {
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var refreshToken = Convert .ToBase64String(tokenBytes);

            var tokenInUser = _authContext.Users
                .Any(a => a.RefreshToken == refreshToken);

            if (tokenInUser)
            {
                return CreateRefreshToken();
            }
            return refreshToken;
        }

        private ClaimsPrincipal GetPrincipleFromExpiryToken(string token)
        {
            var key = Encoding.ASCII.GetBytes("veryverysecret...");
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = false
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token,tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;

            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("This is  invalid Token");
            return principal;

        }

        [Authorize]
        [HttpGet]
        public async Task<ActionResult<User>> GetAllUsers()
        {
            return Ok(await _authContext.Users.ToListAsync());
        }

        [HttpPost("refresh")]

        public async Task<IActionResult> Refresh(TokenAPIDbo tokenAPIDbo)
        {
            if(tokenAPIDbo is null)
                return BadRequest("Invalid Client Request");    
            string accessToken = tokenAPIDbo.AccessToken;
            string refreshToken = tokenAPIDbo.RefreshToken; 
            var principal = GetPrincipleFromExpiryToken(accessToken);
            var username = principal.Identity.Name;
            var user = await _authContext.Users.FirstOrDefaultAsync(u => u.Username == username);

            if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
                return BadRequest("Invalid Request");
            var newAccessToken = CreateJWT(user);
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            await _authContext.SaveChangesAsync();
            return Ok(new TokenAPIDbo()
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken,
            });

            
        }
        
    }
}
