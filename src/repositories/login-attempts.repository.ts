
import { Injectable } from '@nestjs/common';
import { BaseRepository } from 'src/shared/base.repository';
import { LoginAttempt } from '@entities/login_attempts';
import { EntityManager } from 'typeorm';

@Injectable()
export class LoginAttemptRepository extends BaseRepository<LoginAttempt> {
  constructor(manager: EntityManager) {
    super(LoginAttempt, manager);
  }

  async recordLoginAttempt(loginAttempt: LoginAttempt): Promise<LoginAttempt> {
    loginAttempt.attempted_at = new Date();
    return await this.manager.save(LoginAttempt, loginAttempt);
  }
}
