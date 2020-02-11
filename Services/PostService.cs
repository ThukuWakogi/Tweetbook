using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using TweetBook.Data;
using TweetBook.Domain;

namespace TweetBook.Services
{
    public class PostService : IPostService
    {
        private readonly DataContext _dataContext;

        public PostService(DataContext dataContext) => _dataContext = dataContext;

        public async Task<List<Post>> GetPostsAsync() => await _dataContext.Posts.ToListAsync();

        public async Task<Post> GetPostByIdAsync(Guid postId) => await _dataContext.Posts.SingleOrDefaultAsync(x => x.Id == postId);

        public async Task<bool> CreatePostAsync(Post post)
        {
            await _dataContext.Posts.AddAsync(post);
            var created = await _dataContext.SaveChangesAsync();

            return created > 0;
        }

        public async Task<bool> UpdatePostAsync(Post postToUpdate)
        {
            _dataContext.Posts.Update(postToUpdate);
            var updated = await _dataContext.SaveChangesAsync();

            return updated > 0;
        }

        public async Task<bool> DeletePostAsync(Guid postId)
        {
            if (await GetPostByIdAsync(postId) == null) return false;

            _dataContext.Posts.Remove(await GetPostByIdAsync(postId));
            var deleted = await _dataContext.SaveChangesAsync();

            return deleted > 0;
        }

        public async Task<bool> UserOwnsPostAsync(Guid postId, string userId)
        {
            Post post = await _dataContext.Posts.AsNoTracking().SingleOrDefaultAsync(x => x.Id == postId);

            if (post == null) return false;

            if (post.UserId != userId) return false;

            return true;
        }
    }
}
