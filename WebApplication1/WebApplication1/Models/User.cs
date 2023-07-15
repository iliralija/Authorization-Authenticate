﻿using Microsoft.VisualBasic;
using System.ComponentModel.DataAnnotations;
using System.Data;

namespace WebApplication1.Models
{
   
    public class User
    {
        [Key]
        public int Id { get; set; }

        public string Firstname { get; set; }

        public string Lastname { get; set; }

        public string Email { get; set; }

        public string Username { get; set; }

        public string Password { get; set; }

        public string Token { get; set; }

        public string Role { get; set; }

        public string RefreshToken { get; set; }

        public DateTime RefreshTokenExpiryTime { get; set; }
    }
}
