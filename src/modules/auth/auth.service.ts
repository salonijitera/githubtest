import { BadRequestException, Injectable, InternalServerErrorException, MoreThan } from '@nestjs/common';
import { UserRepository } from 'src/repositories/users.repository';
import { EmailVerificationTokenRepository } from 'src/repositories/email-verification-tokens.repository';
import { LoginAttemptRepository } from 'src/repositories/login-attempts.repository';
import * as bcrypt from 'bcryptjs';
import { User } from 'src/entities/users';
import { EmailVerificationToken } from 'src/entities/email_verification_tokens';
import { LoginAttempt } from 'src/entities/login_attempts';

export class LoginDto {
  username: string;
  password_hash: string;
  ip_address: string;
}

export class LoginResponseDto {
  message: string;
  statusCode: number;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly emailVerificationTokenRepository: EmailVerificationTokenRepository,
    private readonly loginAttemptRepository: LoginAttemptRepository,
  ) {}

  async login(loginDto: LoginDto): Promise<LoginResponseDto> {
    const { username, password_hash, ip_address } = loginDto;

    if (!username || !password_hash) {
      throw new BadRequestException('Username and password hash are required.');
    }

    try {
      const user = await this.userRepository.findOne({ where: { username } });

      if (!user) {
        return { message: 'User not found.', statusCode: 404 };
      }

      const passwordIsValid = await bcrypt.compare(password_hash, user.password_hash);

      const loginAttempt = new LoginAttempt();
      loginAttempt.user_id = user.id;
      loginAttempt.attempted_at = new Date();
      loginAttempt.ip_address = ip_address;
      loginAttempt.successful = passwordIsValid && user.email_verified;

      await this.loginAttemptRepository.save(loginAttempt);

      if (passwordIsValid && user.email_verified) {
        return { message: 'Login successful.', statusCode: 200 };
      } else if (!user.email_verified) {
        return { message: 'Email not verified.', statusCode: 401 };
      } else {
        return { message: 'Incorrect credentials.', statusCode: 401 };
      }
    } catch (error) {
      throw new InternalServerErrorException(`An error occurred during the login process: ${error.message}`);
    }
  }

  async verifyEmailToken(token: string): Promise<{ message: string; statusCode: number }> {
    if (!token) {
      throw new BadRequestException('Token is required');
    }

    try {
      const emailVerificationToken = await this.emailVerificationTokenRepository.findOne({
        where: {
          token: token,
          used: false,
          expires_at: MoreThan(new Date()),
        },
      });

      if (!emailVerificationToken) {
        throw new BadRequestException('Token is invalid or expired');
      }

      emailVerificationToken.used = true;
      await this.emailVerificationTokenRepository.save(emailVerificationToken);

      const user = await this.userRepository.findOne(emailVerificationToken.user_id);
      if (user) {
        user.email_verified = true;
        await this.userRepository.save(user);
      }

      return {
        message: 'Email verified successfully',
        statusCode: 200,
      };
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      throw new InternalServerErrorException('An error occurred during the email verification process');
    }
  }

  // Other service methods...
}
