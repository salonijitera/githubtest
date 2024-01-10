import { HealthCheckModule } from './health-check/health-check.module';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';

export default [HealthCheckModule, AuthModule, UsersModule];
