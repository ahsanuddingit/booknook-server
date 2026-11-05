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
   BORROW SYSTEM ROUTES
   ========================== */

// 6. POST /borrows — Borrow a book with Challenge validations (Private Route)
app.post("/borrows", verifyToken, async (req, res) => {
  try {
    const { bookId, bookTitle, bookImage, userEmail, borrowDate, returnDate } = req.body;

    if (!ObjectId.isValid(bookId)) {
      return res.status(400).send({ message: "Invalid Book ID" });
    }

    // Challenge Check: Check if user already borrowed this book and hasn't returned it
    const existingBorrow = await borrowsCollection.findOne({
      bookId: new ObjectId(bookId),
      userEmail: userEmail || req.user.email
    });

    if (existingBorrow) {
      return res.status(400).send({ message: "You have already borrowed this book and haven't returned it yet!" });
    }

    // Check if the book has available copies > 0
    const book = await booksCollection.findOne({ _id: new ObjectId(bookId) });
    if (!book) {
      return res.status(404).send({ message: "Book not found!" });
    }

    if (book.availableCopies <= 0) {
      return res.status(400).send({ message: "Sorry, this book is currently out of stock / Not Available." });
    }

    // Insert borrow record
    const borrowRecord = {
      bookId: new ObjectId(bookId),
      bookTitle,
      bookImage,
      userEmail: userEmail || req.user.email,
      borrowDate: borrowDate || new Date(),
      returnDate: returnDate || new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days default
    };

    const result = await borrowsCollection.insertOne(borrowRecord);

    // Decrease availableCopies by 1 using $inc
    await booksCollection.updateOne(
      { _id: new ObjectId(bookId) },
      { $inc: { availableCopies: -1 } }
    );

    res.status(201).send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to borrow book", error: error.message });
  }
});

// 7. GET /borrows — Get borrows of the logged-in user (Private Route)
app.get("/borrows", verifyToken, async (req, res) => {
  try {
    const userEmail = req.user.email; // Extracted securely from verified token
    const result = await borrowsCollection.find({ userEmail }).toArray();
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch borrowed books", error: error.message });
  }
});

// 8. DELETE /borrows/:id — Return a book and increment available copies (Private Route)
app.delete("/borrows/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).send({ message: "Invalid Borrow Record ID format" });
    }

    // Find the borrow record first to get the corresponding bookId
    const borrowRecord = await borrowsCollection.findOne({ _id: new ObjectId(id) });
    if (!borrowRecord) {
      return res.status(404).send({ message: "Borrow record not found!" });
    }

    // Delete the borrow record
    const result = await borrowsCollection.deleteOne({ _id: new ObjectId(id) });

    // Increment availableCopies by 1 using $inc
    await booksCollection.updateOne(
      { _id: new ObjectId(borrowRecord.bookId) },
      { $inc: { availableCopies: 1 } }
    );

    res.send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to return book", error: error.message });
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