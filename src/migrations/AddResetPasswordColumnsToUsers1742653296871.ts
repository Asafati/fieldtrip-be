import { MigrationInterface, QueryRunner } from "typeorm";

export class AddResetPasswordColumnsAgain1742653299999 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE users
      ADD COLUMN resetPasswordToken VARCHAR(255),
      ADD COLUMN resetPasswordExpires TIMESTAMP;
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE users
      DROP COLUMN resetPasswordToken,
      DROP COLUMN resetPasswordExpires;
    `);
  }
}
