
import { Body, Controller, HttpCode, HttpStatus, Post, BadRequestException, ConflictException, InternalServerErrorException } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { LoginDto } from './dtos/login.dto';
import { RegisterUserDto } from './dtos/register-user.dto';

@Controller()
@ApiTags('Auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() loginDto: LoginDto) {
    const loginResult = await this.authService.login(loginDto);
    return {
      message: loginResult.message,
      statusCode: loginResult.statusCode
    };
  }

  @Post('/api/users/register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() registerUserDto: RegisterUserDto) {
    try {
      const registrationResult = await this.authService.registerUser(registerUserDto.username, registerUserDto.passwordHash, registerUserDto.email);
      return {
        status: HttpStatus.CREATED,
        message: registrationResult.message
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
}
