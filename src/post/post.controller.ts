import {
  Body,
  Controller,
  Delete,
  Get,
  NotFoundException,
  Param,
  Post,
  Put,
  Query,
  Req,
} from '@nestjs/common';
import { JwtPayloadDto } from 'src/auth/dto/jwt-payload.dto';
import { CreatePostDTO } from './create-post.dto';
import { PostService } from './post.service';
import { Posts } from './posts.entity';
import { ApiParam, ApiQuery } from '@nestjs/swagger';

@Controller('post')
export class PostController {
  constructor(private readonly postService: PostService) {}
  @Post()
  async create(@Req() request: Request, @Body() createPostDTO: CreatePostDTO) {
    const posts: Posts = new Posts();
    const userJwtPayload: JwtPayloadDto = request['user'];
    posts.content = createPostDTO.content;
    posts.image_url = createPostDTO.imageUrl;
    posts.title = createPostDTO.title;
    posts.user_id = userJwtPayload.sub;
    await this.postService.save(posts);
  }

  @Get()
  @ApiQuery({ name: 'page', required: false, type: Number, example: 1 })
  @ApiQuery({ name: 'limit', required: false, type: Number, example: 10 })
  async findAll(
    @Req() request: Request,
    @Query('page') page: number = 1,
    @Query('limit') limit: number = 10,
  ): Promise<Posts[]> {
    const userJwtPayload: JwtPayloadDto = request['user'];
    return await this.postService.findByUserId(userJwtPayload.sub, page, limit);
  }

  @Get(':id')
  @ApiParam({ name: 'id', type: Number, description: 'ID of the post' })
  async findOne(
    @Req() request: Request,
    @Param('id') id: number,
  ): Promise<Posts> {
    const userJwtPayload: JwtPayloadDto = request['user'];
    return await this.postService.findByUserIdAndPostId(userJwtPayload.sub, id);
  }

  @Put(':id')
  @ApiParam({ name: 'id', type: Number, description: 'ID of the post' })
  async updateOne(
    @Req() request: Request,
    @Param('id') id: number,
    @Body() createPostDTO: CreatePostDTO,
  ) {
    const userJwtPayload: JwtPayloadDto = request['user'];
    const post: Posts = await this.postService.findByUserIdAndPostId(
      userJwtPayload.sub,
      id,
    );
    if (post.id == null) {
      throw new NotFoundException();
    }
    post.content = createPostDTO.content;
    post.image_url = createPostDTO.imageUrl;
    post.title = createPostDTO.title;
    await this.postService.save(post);
  }

  @Delete(':id')
  @ApiParam({ name: 'id', type: Number, description: 'ID of the post' })
  async deleteOne(@Req() request: Request, @Param('id') id: number) {
    const userJwtPayload: JwtPayloadDto = request['user'];
    const post: Posts = await this.postService.findByUserIdAndPostId(
      userJwtPayload.sub,
      id,
    );
    if (post.id == null) {
      throw new NotFoundException();
    }
    await this.postService.deleteById(id);
  }
}
