 { IsNotEmpty, IsString, MinLength, ValidateIf } from 'class-validator';
import { IsPassword } from '../../../shared/validators/is-password.validator';

export class UpdatePasswordDto {
  @IsNotEmpty({ message: 'User ID must not be empty' })
  @IsString({ message: 'User ID must be a string' })
  id: string;

  @IsNotEmpty({ message: 'Password hash must not be empty' })
  @IsString({ message: 'Password hash must be a string' })
  password_hash: string;

  @IsNotEmpty({ message: 'Current password is required.' })
  @IsString({ message: 'Current password must be a string' })
  current_password: string;

  @IsNotEmpty({ message: 'New password must be at least 8 characters long.' })
  @IsPassword({ message: 'New password does not meet criteria' })
  @MinLength(8, { message: 'New password must be at least 8 characters long.' })
  new_password: string;

  @ValidateIf(o => o.new_password !== o.current_password, { message: 'New password must be different from the current password.' })
  validateNewPasswordIsDifferent(value: string): boolean {
    return value !== this.current_password;
  }

  @IsNotEmpty({ message: 'New password hash must not be empty' })
  @IsPassword({ message: 'New password does not meet criteria' })
  new_password_hash: string;
}
