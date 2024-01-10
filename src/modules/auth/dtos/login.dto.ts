import { IsNotEmpty } from 'class-validator';

export class LoginDto {
  @IsNotEmpty({ message: 'Username is required.' })
  username: string;

  @IsNotEmpty({ message: 'Password hash is required.' })
  password_hash: string;

  @IsNotEmpty({ message: 'IP address is required.' })
  ip_address: string;

  constructor(username: string, password_hash: string, ip_address: string) {
    this.username = username;
    this.password_hash = password_hash;
    this.ip_address = ip_address;
  }
}
