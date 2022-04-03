import mongoose from "mongoose";
import { DB_URL } from "../../Config";
import consola from "consola";
mongoose
  .connect(DB_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then((data) => {
    consola.success(`Mongo DB Connected`);
  })
  .catch((error) => {
    consola.error(error);
  });
