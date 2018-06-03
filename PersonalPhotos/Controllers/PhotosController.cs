using System.IO;
using System.Threading.Tasks;
using Core.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using PersonalPhotos.ViewModels;

namespace PersonalPhotos.Controllers
{
    public class PhotosController : Controller
    {
        private readonly IFileStorage _fileStorage;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IKeyGenerator _keyGenerator;
        private readonly IPhotoMetaData _photoMetaData;

        public PhotosController(IKeyGenerator keyGenerator, IHttpContextAccessor httpContextAccessor,
            IPhotoMetaData photoMetaData, IFileStorage fileStorage)
        {
            _keyGenerator = keyGenerator;
            _httpContextAccessor = httpContextAccessor;
            _photoMetaData = photoMetaData;
            _fileStorage = fileStorage;
        }
        //[Authorize("EditorOver18")] //2/6/2018 it's not working
        [Authorize(Roles = "Editor")]
        public IActionResult Upload()
        {
            return View();
        }

        [HttpPost]
        //[Authorize("EditorOver18")] //2/6/2018 it's not working
        [Authorize(Roles = "Editor")]
        public async Task<IActionResult> Upload(PhotoUploadViewModel model)
        {
            if (ModelState.IsValid)
            {
                var userName = User.Identity.Name;
                var uniqueKey = _keyGenerator.GetKey(userName);

                var fileName = Path.GetFileName(model.File.FileName);
                await _photoMetaData.SavePhotoMetaData(userName, model.Description, fileName);
                await _fileStorage.StoreFile(model.File, uniqueKey);
            }
            return RedirectToAction("Display");
        }

        [Authorize]
        public IActionResult Display()
        {
            var userName = User.Identity.Name;
            return View("Display", userName);
        }
    }
}