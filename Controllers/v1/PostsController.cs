using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using TweetBook.Contracts.v1;
using TweetBook.Controllers.v1.Requests;
using TweetBook.Controllers.v1.Responses;
using TweetBook.Domain;
using TweetBook.Extensions;
using TweetBook.Services;

namespace TweetBook.Controllers.v1
{
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class PostsController : Controller
    {
        private readonly IPostService _postService;

        public PostsController(IPostService postService) 
        {
            _postService = postService;
        }

        [HttpGet(ApiRoutes.Posts.GetAll)]
        public async Task<IActionResult> GetAllAsync()
        {
            return Ok(await _postService.GetPostsAsync());
        }

        [HttpGet(ApiRoutes.Posts.Get)]
        public async Task<IActionResult> Get([FromRoute] Guid postId)
        {
            Post post = await _postService.GetPostByIdAsync(postId);

            if (post == null) return NotFound();

            return Ok(post);
        }

        [HttpPut(ApiRoutes.Posts.Update)]
        public async Task<IActionResult> UpdateAsync([FromRoute] Guid postId, [FromBody] UpdatePostRequest request)
        {
            bool userOwnsPost = await _postService.UserOwnsPostAsync(postId, HttpContext.GetUserId());

            if (!userOwnsPost) return BadRequest(new { error = "You do not own this post" } );

            Post post = await _postService.GetPostByIdAsync(postId);
            post.Name = request.Name;

            bool updated = await _postService.UpdatePostAsync(post);

            if (updated) return Ok(post);

            return NotFound();
        }

        [HttpPost(ApiRoutes.Posts.Create)]
        public async Task<IActionResult> CreateAsync([FromBody] CreatePostRequest postRequest)
        {
            Post post = new Post
            {
                Name = postRequest.Name,
                UserId = HttpContext.GetUserId()
            };
            await _postService.CreatePostAsync(post);
            string baseUrl = $"{HttpContext.Request.Scheme}://{HttpContext.Request.Host.ToUriComponent()}";
            string locationUri = baseUrl + "/" + ApiRoutes.Posts.Get.Replace("{postId}", post.Id.ToString());
            PostResponse response = new PostResponse { Id = post.Id };

            return Created(locationUri, response);
        }

        [HttpDelete(ApiRoutes.Posts.Delete)]
        public async Task<IActionResult> DeleteAsync([FromRoute] Guid postId)
        {
            if (await _postService.DeletePostAsync(postId)) return NoContent();

            bool userOwnsPost = await _postService.UserOwnsPostAsync(postId, HttpContext.GetUserId());

            if (!userOwnsPost) return BadRequest(new { error = "You do not own this post" });

            return NotFound();
        }
    }
}
