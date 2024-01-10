import { IsNotEmpty } from 'class-validator';

export class VerifyEmailDto {
  @IsNotEmpty({ message: 'Token should not be empty' })
  token: string;
}

