import { IsNotEmpty } from 'class-validator';

export class VerifyEmailDto {
  @IsNotEmpty({ message: 'Verification token is required.' })
  token: string;
}

