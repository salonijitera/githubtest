import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { UserRepository } from 'src/repositories/users.repository';
import * as bcrypt from 'bcryptjs';
import { User } from 'src/entities/users';

@Injectable()
export class UsersService {
  constructor(private readonly userRepository: UserRepository) {}

  async updatePassword(id: number, password_hash: string, new_password_hash: string): Promise<{ message: string, statusCode: number }> {
    if (!id || !password_hash || !new_password_hash) {
      throw new BadRequestException('Missing required parameters');
    }

    const user = await this.userRepository.findOneBy({ id });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const passwordIsValid = await bcrypt.compare(password_hash, user.password_hash);
    if (!passwordIsValid) {
      throw new BadRequestException('Invalid current password');
    }

    const newEncryptedPassword = await bcrypt.hash(new_password_hash, 10);
    user.password_hash = newEncryptedPassword;
    user.updated_at = new Date();

    try {
      await this.userRepository.save(user);
      return {
        message: 'Password updated successfully',
        statusCode: 200
      };
    } catch (error) {
      throw new BadRequestException('Failed to update password');
    }
  }
}
