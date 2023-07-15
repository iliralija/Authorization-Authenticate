import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Injectable({
  providedIn: 'root'
})
export class ApiService {
  private baseUrl = 'https://localhost:7170/api/User/'

  constructor(private http: HttpClient) { }

  getUser(){
    return this.http.get<any>(this.baseUrl);
  }
}
