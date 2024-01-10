import {
  registerDecorator,
  ValidationArguments,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
} from 'class-validator';
import { Injectable } from '@nestjs/common';
import { EntitySchema, Not, DataSource, ObjectType, FindOptionsWhere } from 'typeorm';
import { UserRepository } from 'src/repositories/users.repository';
import { User } from 'src/entities/users';
import { EmailVerificationToken } from '@entities/email_verification_tokens';

export interface UniqueValidationArguments<E> extends ValidationArguments {
  constraints: [EntitySchema<E> | ObjectType<E>];
}

@ValidatorConstraint({ name: 'isEntityUnique', async: true })
@Injectable()
export class EntityUniqueValidator implements ValidatorConstraintInterface {
  constructor(protected readonly dataSource: DataSource, protected readonly userRepository?: UserRepository) {}

  async validate<E>(value: any, args: UniqueValidationArguments<E>) {
    const [EntityClass] = args.constraints;

    // Determine if the validation is for the User entity and the property is 'email'
    if (EntityClass === User && args.property === 'email') {
      return this.isEmailUnique(value);
    }

    // For other entities or properties, proceed with the existing unique validation
    const entityRepo = await this.dataSource.getRepository(EntityClass);

    const primaryKey = await entityRepo.metadata.primaryColumns[0].propertyName;

    const query = {
      [args.property]: value,
      ...(args.object[primaryKey] && {
        [primaryKey]: Not(args.object[primaryKey]),
      }),
    } as FindOptionsWhere<E>;

    const count = await entityRepo.count({ where: query });

    return count === 0;
  }

  async isEmailUnique(email: string): Promise<boolean> {
    if (!this.userRepository) {
      throw new Error('UserRepository is not provided');
    }
    const user = await this.userRepository.findOne({ where: { email } });
    return !user;
  }

  async isEmailVerificationTokenUnique(token: string): Promise<boolean> {
    const entityRepo = await this.dataSource.getRepository(EmailVerificationToken);
    const count = await entityRepo.count({
      where: { token, used: false },
    });
    return count === 0;
  }

  defaultMessage<E>(args: UniqueValidationArguments<E>) {
    if (args.constraints[0] === User && args.property === 'email') {
      return 'The email is already in use.';
    }
    return `A ${this.dataSource.getRepository(args.constraints[0]).metadata.tableName} with this ${
      args.property
    } already exists`;
  }
}

export function EntityUnique<E>(
  entity: EntitySchema<E> | ObjectType<E>,
  validationOptions?: ValidationOptions,
) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [entity],
      validator: EntityUniqueValidator,
    });
  };
}
