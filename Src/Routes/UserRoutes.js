import express from "express";
let UserRoutes = express.Router();
import { UserController } from "../Controller";
import { Authentication, Authorization } from "../Middleware";

// [ + ] User Routes
UserRoutes.post("/register", UserController.registerUser);
UserRoutes.post("/users/:id/verify/:token", UserController.verifyEmail);
UserRoutes.post("/login", UserController.login);
UserRoutes.post("/password/forgot", UserController.forgotPassword);
UserRoutes.put("/password/reset/:token", UserController.resetPassword);
UserRoutes.get("/logout", UserController.logout);

// [ + ]After Login this url is used for user
UserRoutes.get("/profile", Authentication, UserController.getUserDetails);
UserRoutes.put(
  "/changePassword",
  Authentication,
  UserController.updatePassword
);
UserRoutes.put(
  "/edit_profile",
  Authentication,
  UserController.updateUserDetails
);

// [ + ] Admin Credentials
UserRoutes.get(
  "/details",
  Authentication,
  Authorization("admin"),
  UserController.getAllUserDetails
);
UserRoutes.get(
  "/admin/user/:id",
  Authentication,
  Authorization("admin"),
  UserController.getSingleUser
);
UserRoutes.put(
  "/admin/user/:id",
  Authentication,
  Authorization("admin"),
  UserController.updateUserRole
);
UserRoutes.delete(
  "/admin/user/:id",
  Authentication,
  Authorization("admin"),
  UserController.deleteUser
);
export default UserRoutes;
