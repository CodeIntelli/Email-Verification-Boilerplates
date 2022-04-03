import mongoose from "mongoose";

const TokenSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.ObjectId,
    required: true,
    ref: "user",
    unique: true,
  },
  token: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: 1200 }, // 20 minutes
});

let TokenModel = mongoose.model("TokenVerification", TokenSchema);

export default TokenModel;
