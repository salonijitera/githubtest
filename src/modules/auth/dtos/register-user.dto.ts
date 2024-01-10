import { IsEmail, IsNotEmpty, IsString } from 'class-validator';
import { IsPassword } from 'src/shared/validators/is-password.validator';
import { EntityUnique } from 'src/shared/validators/entity-unique.validator';
import { User } from 'src/entities/users.ts';

export class RegisterUserDto {
  @IsString()
  @IsNotEmpty({ message: 'Username is required.' })
  username: string;

  @IsString()
  @IsNotEmpty()
  @IsPassword({ message: 'Password must be at least 8 characters long.' })
  passwordHash: string;

  @IsEmail()
  @IsNotEmpty({ message: 'Invalid email format.' })
  @EntityUnique(User, { message: 'Email is already in use.' })
  email: string;
}
