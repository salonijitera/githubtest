import { Controller, Put, Body, HttpCode, HttpStatus, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { UpdatePasswordDto } from './dto/update-password.dto';
import { UsersService } from './users.service';

@Controller('api/users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Put('/update-password')
  @UseGuards(AuthGuard('jwt'))
  @HttpCode(HttpStatus.OK)
  async updatePassword(@Body() updatePasswordDto: UpdatePasswordDto) {
    try {
      const { current_password, new_password } = updatePasswordDto;

      if (!current_password) {
        return {
          statusCode: HttpStatus.BAD_REQUEST,
          message: 'Current password is required.'
        };
      }

      if (new_password.length < 8) {
        return {
          statusCode: HttpStatus.BAD_REQUEST,
          message: 'New password must be at least 8 characters long.'
        };
      }

      if (new_password === current_password) {
        return {
          statusCode: HttpStatus.BAD_REQUEST,
          message: 'New password must be different from the current password.'
        };
      }

      return await this.usersService.updatePassword(updatePasswordDto.id, current_password, new_password);
    } catch (error) {
      throw error;
    }
  }
}
