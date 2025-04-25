import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreatePostsTable1743923426639 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
          CREATE TABLE posts (
              id SERIAL PRIMARY KEY,
              user_id INTEGER NOT NULL,
              title VARCHAR(255) NOT NULL,
              content TEXT,
              image_url TEXT,
              created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
              updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,

              CONSTRAINT fk_user
                  FOREIGN KEY(user_id) 
                  REFERENCES Users(id)
                  ON DELETE CASCADE
          );
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE posts;`)
  }
}
