import { Injectable } from '@angular/core';
import { CanActivate, Router } from '@angular/router';
import { AuthService } from '../services/auth.service';


@Injectable({
  providedIn: 'root'
})
export class AuthGuard implements CanActivate {
  constructor(private auth: AuthService, private router: Router) { 

  }
  canActivate(): boolean {
    if(this.auth.isLoggedIn()){
      return true;
    }else{
      alert("You must be logged in first!");
      this.router.navigate(['login']);
    return false;
  }
 }
}
