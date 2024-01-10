
import { BadRequestException, Injectable, InternalServerErrorException, MoreThan } from '@nestjs/common';
import { EmailVerificationTokenRepository } from 'src/repositories/email-verification-tokens.repository';
import { UserRepository } from 'src/repositories/users.repository';
import { EmailVerificationToken } from 'src/entities/email_verification_tokens';
import { User } from 'src/entities/users';

@Injectable()
export class AuthService {
  constructor(
    private readonly emailVerificationTokenRepository: EmailVerificationTokenRepository,
    private readonly userRepository: UserRepository,
  ) {}

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
