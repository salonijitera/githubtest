import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  BadRequestException,
  NotFoundException,
  ConflictException,
  InternalServerErrorException,
  Res,
} from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { LoginDto, LoginResponseDto } from './dtos/login.dto';
import { RegisterUserDto } from './dtos/register-user.dto';
import { VerifyEmailDto } from './dtos/verify-email.dto';
import { Response } from 'express';

@Controller()
@ApiTags('Auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/api/users/login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() loginDto: LoginDto, @Res() res: Response) {
    const loginResult: LoginResponseDto = await this.authService.login(loginDto);
    if (loginResult.statusCode === HttpStatus.OK) {
      return res.status(HttpStatus.OK).json({
        message: loginResult.message,
        access_token: loginResult.access_token,
      });
    }
    return res.status(loginResult.statusCode).json({ message: loginResult.message });
  }

  @Post('/api/users/register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() registerUserDto: RegisterUserDto) {
    try {
      const registrationResult = await this.authService.registerUser(registerUserDto.username, registerUserDto.passwordHash, registerUserDto.email);
      return {
        status: HttpStatus.CREATED,
        message: registrationResult.message,
      };
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw new BadRequestException(error.response);
      } else if (error.status === HttpStatus.CONFLICT) {
        throw new ConflictException(error.response);
      } else {
        throw new InternalServerErrorException('An unexpected error occurred on the server.');
      }
    }
  }

  @Post('/api/users/verify-email')
  @HttpCode(HttpStatus.OK)
  async verifyEmail(@Body() verifyEmailDto: VerifyEmailDto) {
    try {
      const verifyResult = await this.authService.verifyEmailToken(verifyEmailDto.token);
      return {
        status: verifyResult.statusCode,
        message: verifyResult.message,
      };
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw new BadRequestException(error.response);
      } else if (error instanceof NotFoundException) {
        throw a NotFoundException(error.response);
      } else {
        throw new InternalServerErrorException('An unexpected error occurred');
      }
    }
  }
}
