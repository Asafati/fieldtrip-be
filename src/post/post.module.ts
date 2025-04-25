import { Module } from '@nestjs/common';
import { PostController } from './post.controller';
import { PostService } from './post.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Posts } from './posts.entity';

@Module({
  imports: [TypeOrmModule.forFeature([ Posts ])],
  controllers: [PostController],
  providers: [PostService],
})
export class PostModule {}
