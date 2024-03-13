const express = require("express");
const mongoose = require("mongoose");
const User = require("./routes/user");
const bodyParser = require("body-parser");

const port = 3000;
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use("/api", User);

const connectToDB = async () => {
  try {
    await mongoose.connect("mongodb://localhost:27017/SignUp");
    console.log("connect to mongoDB");
  } catch (error) {
    console.log(error);
    process.exit(1);
  }
};

connectToDB();

app.listen(port, () => {
  console.log(`Server is running at PORT = ${port}`);
});
