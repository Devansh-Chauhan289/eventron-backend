import multer from "multer";

const storage = multer.diskStorage({
  filename: function (req,file,cb) {
    cb(null, file.originalname)
  }
});

const upload = multer({
  storage: storage,
  limits: {
      fileSize: 10 * 1024 * 1024 // 10MB limit (you can adjust this based on your needs)
  }
}).single('media'); 

export {upload}