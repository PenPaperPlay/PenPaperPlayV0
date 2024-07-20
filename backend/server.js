import express from "express";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import cookieParser from 'cookie-parser';
import cookieSession from "cookie-session";
import routes from "./routes/routes.js"
import connectDB from "./config/db.js"

dotenv.config();

const app = express();

/*middleware */
app.use(express.json());
app.use(cookieParser());
app.use(
    cookieSession({
        name: "session",
        keys: ["live-streaming-app"],
        maxAge: 24 * 60 * 60 * 100,
    })
);

/** routes */
app.use("/", routes)
app.get("/", (req, res) => {
    res.send("<h1> Gaming Coach - Teaching App </h1>")
})

const PORT = 8080;

const startServer = () => {
    try {

        connectDB(process.env.MONGODB_URL);
        app.listen(PORT, () => {
            console.log(`Server is started on port ${PORT}`)
        })

    } catch (error) {
        console.log(error)
    }
}

startServer();
