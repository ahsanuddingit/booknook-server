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



// Optional: Get featured/newest books for Home page
app.get("/featured-books", async (req, res) => {
  try {
    const result = await booksCollection.find().sort({ createdAt: -1 }).limit(6).toArray();
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch featured books", error: error.message });
  }
});

// 2. GET /books/:id — Get a single book (Public / Private)
app.get("/books/:id", async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).send({ message: "Invalid Book ID format" });
    }
    const result = await booksCollection.findOne({ _id: new ObjectId(id) });
    if (!result) {
      return res.status(404).send({ message: "Book not found" });
    }
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch book details", error: error.message });
  }
});

// 3. POST /books — Add a new book (Private Route)
app.post("/books", verifyToken, async (req, res) => {
  try {
    const bookData = req.body;
    const newBook = {
      ...bookData,
      totalCopies: parseInt(bookData.totalCopies) || 1,
      availableCopies: parseInt(bookData.totalCopies) || 1,
      createdAt: new Date()
    };
    const result = await booksCollection.insertOne(newBook);
    res.status(201).send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to add book", error: error.message });
  }
});


// 4. PATCH /books/:id — Update a book (Private Route)
app.patch("/books/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const updatedData = req.body;
   
    if (!ObjectId.isValid(id)) {
      return res.status(400).send({ message: "Invalid Book ID format" });
    }

    const result = await booksCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updatedData }
    );
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to update book", error: error.message });
  }
});


// 5. DELETE /books/:id — Delete a book (Private Route)
app.delete("/books/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).send({ message: "Invalid Book ID format" });
    }
    const result = await booksCollection.deleteOne({ _id: new ObjectId(id) });
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to delete book", error: error.message });
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