import { IsNotEmpty, IsString } from 'class-validator';
import { IsPassword } from '@decorators/is-password.decorator';

export class UpdatePasswordDto {
  @IsNotEmpty({ message: 'User ID must not be empty' })
  @IsString({ message: 'User ID must be a string' })
  id: string;

  @IsNotEmpty({ message: 'Password hash must not be empty' })
  @IsString({ message: 'Password hash must be a string' })
  password_hash: string;

  @IsNotEmpty({ message: 'New password hash must not be empty' })
  @IsPassword({ message: 'New password does not meet criteria' })
  new_password_hash: string;
}
