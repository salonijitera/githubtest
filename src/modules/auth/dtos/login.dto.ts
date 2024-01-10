
import { IsNotEmpty } from 'class-validator';

export class LoginDto {
  @IsNotEmpty({ message: 'Username is required.' })
  username: string;

  @IsNotEmpty({ message: 'Password is required.' })
  password: string;

  @IsNotEmpty({ message: 'IP address is required.' })
  ip_address: string;

  constructor(username: string, password: string, ip_address: string) {
    this.username = username;
    this.password = password;
    this.ip_address = ip_address;
  }
}
