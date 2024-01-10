import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserRepository } from 'src/repositories/users.repository';
import { EmailVerificationTokenRepository } from 'src/repositories/email-verification-tokens.repository';
import { LoginAttemptRepository } from 'src/repositories/login-attempts.repository';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { EmailModule } from 'src/shared/email/email.module'; // Assuming EmailModule exists

@Module({
  imports: [
    TypeOrmModule.forFeature([
      UserRepository,
      EmailVerificationTokenRepository,
      LoginAttemptRepository,
    ]),
    EmailModule,
  ],
  providers: [AuthService],
  controllers: [AuthController],
  exports: [AuthService], // Export AuthService if it will be used outside of the AuthModule
})
export class AuthModule {}