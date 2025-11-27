const path = require("path");

require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoDBStore = require("connect-mongodb-session")(session);
const csrf = require("csurf");
const flash = require("connect-flash");
const multer = require("multer");

const errorController = require("./controllers/error");
const User = require("./models/user");

const MONGODB_URI = process.env.MONGODB_URI;

const app = express();
const store = new MongoDBStore(
  {
    uri: MONGODB_URI,
    collection: "sessions",
  }
);
const csrfProtection = csrf();

const fileStorage = multer.diskStorage({
  destination: (request, file, cb) => {
    cb(null, "images");
  },
  filename: (request, file, cb) => {
    cb(null, new Date().toISOString() + "-" + file.originalname);
  },
});

const fileFilter = (request, file, cb) => {
  if (
    file.mimetype === "image/png" ||
    file.mimetype === "image/jpg" ||
    file.mimetype === "image/jpeg"
  ) {
    cb(null, true);
  } else {
    cb(null, false);
  }
};

app.set("view engine", "ejs");
app.set("views", "views");

const adminRoutes = require("./routes/admin");
const shopRoutes = require("./routes/shop");
const authRoutes = require("./routes/auth");

app.use(bodyParser.urlencoded({ extended: false }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "my secret",
    resave: false,
    saveUninitialized: false,
    store: store,
  })
);
app.use(
  multer({ storage: fileStorage, fileFilter: fileFilter }).single("image")
);
app.use(express.static(path.join(__dirname, "public")));
app.use("/images", express.static(path.join(__dirname, "images")));

app.use(csrfProtection);
app.use(flash());

app.use((request, response, next) => {
  response.locals.isAuthenticated = request.session ? request.session.isLoggedIn : false;
  response.locals.csrfToken = request.csrfToken();
  next();
});

app.use((request, response, next) => {
  // throw new Error('Sync Dummy');
  if (!request.session.user) {
    return next();
  }
  User.findById(request.session.user._id)
    .then((user) => {
      if (!user) {
        return next();
      }
      request.user = user;
      next();
    })
    .catch((err) => {
      next(new Error(err));
    });
});

app.use("/admin", adminRoutes);
app.use(shopRoutes);
app.use(authRoutes);

app.get("/500", errorController.get500);

app.use(errorController.get404);

app.use((error, request, response, next) => {
  console.log(error);
  // response.status(error.httpStatusCode).render(...);
  // response.redirect('/500');
  response.status(500).render("500", {
    pageTitle: "Error!",
    path: "/500",
    isAuthenticated: request.session ? request.session.isLoggedIn : false,
  });
});

mongoose
  .connect(MONGODB_URI)
  .then((result) => {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("MongoDB connection error:", err);
  });
