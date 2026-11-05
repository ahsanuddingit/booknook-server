import "dotenv/config";
import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import { createRemoteJWKSet, jwtVerify } from "jose";

const app = express();
const PORT = process.env.PORT || 8000;

const client = new MongoClient(process.env.MONGODB_URI);

export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.error("MongoDB connection failed:", err);
    process.exit(1);
  }
}

app.use(cors());
app.use(express.json());

const mongoClient = await connectToMongoDB();
const db = mongoClient.db("booknook");
const booksCollection = db.collection("books");
const borrowsCollection = db.collection("borrows");

// Middleware to verify BetterAuth JWT Token & attach user payload to req.user
const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).send({ message: "Unauthorized: No token provided!" });
  }
 
  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).send({ message: "Unauthorized: Invalid token format!" });
  }

  try {
    const JWKS = createRemoteJWKSet(
      new URL(`${process.env.CLIENT_URL}/api/auth/jwks`)
    );
    const { payload } = await jwtVerify(token, JWKS);
    req.user = payload; // Attach decoded user info (e.g., email, id) to request
    next();
  } catch (error) {
    console.error("JWT Verification Error:", error);
    return res.status(401).send({ message: "Unauthorized: Token expired or invalid!" });
  }
};

/* ==========================
   BOOK ROUTES (CRUD)
   ========================== */

// 1. GET /books — Get all books (Public)
app.get("/books", async (req, res) => {
  try {
    const { category, search } = req.query;
    let query = {};
    if (category && category !== "All") {
      query.category = category;
    }
    if (search) {
      query.title = { $regex: search, $options: "i" };
    }
    const result = await booksCollection.find(query).toArray();
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch books", error: error.message });
  }
});



/* ==========================

   HEALTH CHECK & SERVER START

   ========================== */



app.get("/", (req, res) => {

  res.send({ message: "BookNook Server is running fine!" });

});




app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

export default app;