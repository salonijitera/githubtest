import { BadRequestException, Injectable, InternalServerErrorException, MoreThan, NotFoundException } from '@nestjs/common';
import { UserRepository } from '@repositories/users.repository'; // Updated import path
import { EmailVerificationTokenRepository } from 'src/repositories/email-verification-tokens.repository';
import { LoginAttemptRepository } from '@repositories/login-attempts.repository'; // Updated import path
import { EmailService } from 'src/shared/email/email.service';
import * as bcrypt from 'bcryptjs';
import * as crypto from 'crypto';
import { User } from 'src/entities/users';
import { EmailVerificationToken } from 'src/entities/email_verification_tokens';
import { LoginAttempt } from 'src/entities/login_attempts';

export class LoginDto {
  username: string;
  password: string; // Changed from password_hash to password
  ip_address: string;
}

export class LoginResponseDto {
  message: string;
  statusCode: number;
  access_token?: string; // Added optional access_token field
}

@Injectable()
export class AuthService {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly emailVerificationTokenRepository: EmailVerificationTokenRepository,
    private readonly loginAttemptRepository: LoginAttemptRepository,
    private readonly emailService: EmailService,
  ) {}

  async registerUser(username: string, password: string, email: string): Promise<{ message: string; status: string; }> {
    if (!username || !password || !email) {
      throw new BadRequestException('Missing required registration fields');
    }

    const existingUser = await this.userRepository.findOne({ where: { email } });
    if (existingUser) {
      throw new BadRequestException('Email is already in use');
    }

    const encryptedPassword = await bcrypt.hash(password, 10);
    const newUser = new User();
    newUser.username = username;
    newUser.password_hash = encryptedPassword;
    newUser.email = email;
    newUser.email_verified = false;
    newUser.created_at = new Date();
    newUser.updated_at = new Date();

    const createdUser = await this.userRepository.save(newUser);

    const verificationToken = crypto.randomBytes(32).toString('hex');
    const emailVerificationToken = new EmailVerificationToken();
    emailVerificationToken.token = verificationToken;
    emailVerificationToken.expires_at = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours from now
    emailVerificationToken.used = false;
    emailVerificationToken.user_id = createdUser.id;
    emailVerificationToken.created_at = new Date();
    emailVerificationToken.updated_at = new Date();

    await this.emailVerificationTokenRepository.save(emailVerificationToken);

    const emailSent = await this.emailService.sendMail({
      to: email,
      subject: 'Verify Your Email',
      template: 'email-verification',
      context: {
        username: username,
        token: verificationToken,
      },
    });

    if (!emailSent) {
      throw new InternalServerErrorException('Failed to send verification email');
    }

    return {
      message: 'Registration successful, please check your email to verify your account',
      status: 'success',
    };
  }

  async login(loginDto: LoginDto): Promise<LoginResponseDto> {
    const { username, password, ip_address } = loginDto;

    if (!username || !password) {
      throw new BadRequestException('Username and password are required.');
    }

    try {
      const user = await this.userRepository.findOne({ where: { username } });

      if (!user) {
        return { message: 'User not found.', statusCode: 404 };
      }

      const passwordIsValid = await bcrypt.compare(password, user.password_hash);

      const loginAttempt = new LoginAttempt();
      loginAttempt.user_id = user.id;
      loginAttempt.attempted_at = new Date();
      loginAttempt.ip_address = ip_address;
      loginAttempt.successful = passwordIsValid && user.email_verified;

      await this.loginAttemptRepository.save(loginAttempt);

      if (passwordIsValid) {
        if (user.email_verified) {
          // Generate and return access token here
          // The actual token generation logic should be implemented here as per application's requirements
          return { message: 'Login successful.', statusCode: 200, access_token: '...' };
        } else {
          return { message: 'Email not verified.', statusCode: 401 };
        }
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
        throw new NotFoundException('Token is invalid or expired');
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
