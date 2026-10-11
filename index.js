const express = require('express');
require('dotenv').config();

const app = express()
const router = express.Router()

const PORT = process.env.PORT;

app.listen((PORT, () => {
    console.log("Server is listening on", PORT);
}))