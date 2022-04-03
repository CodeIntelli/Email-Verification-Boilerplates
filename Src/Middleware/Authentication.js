import { JWT_SECRET } from "../../Config";
import { TokenModel, UserModel } from "../Models";
import { ErrorHandler, SendEmail } from "../Services";
import jwt from "jsonwebtoken";

const Authentication = async (req, res, next) => {
  try {
    let authToken = req.headers.authorization;

    if (!authToken) {
      return next(
        new ErrorHandler("Please Login to access this resources", 401)
      );
    }

    const token = authToken.split(" ")[1];
    if (token === "undefined") {
      return new ErrorHandler("Please Login to access this resources", 401);
    }
    const decodeData = jwt.verify(token, JWT_SECRET);
    console.log(decodeData);
    // let userVerify = await UserModel.findOne({});

    req.user = await UserModel.findById(decodeData.id);
    console.log(req.user);
    if (!req.user.verified) {
      const token = await TokenModel.create({
        userId: req.user._id,
        token: crypto.randomBytes(32).toString("hex"),
      });
      const url = `${FRONTEND_URL}/users/${req.user._id}/verify/${token.token}`;

      const message = `Your Email Verification token is:- ${url} \n\n If you Don't requested this email then ignore it\n\n `;
      const sendVerifyMail = await SendEmail({
        email: user.email,
        subject: `Email Verification`,
        message,
      });
      if (!sendVerifyMail) {
        return next(
          new ErrorHandler(
            "Something Error Occurred Please Try After Some Time",
            422
          )
        );
      }
      return new ErrorHandler(
        "An Email sent to your account please verify your email address",
        400
      );
    }

    next();
  } catch (error) {
    return next(new ErrorHandler(error, 401));
  }
};

export default Authentication;
