import "dotenv/config";
import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import { createRemoteJWKSet, jwtVerify } from "jose";

const app = express();
const PORT = process.env.PORT || 8000;

const MONGODB_URI = process.env.MONGODB_URI;
const CLIENT_URL = (process.env.CLIENT_URL || "").replace(/\/+$/, "");

// --- env checks: missing CLIENT_URL is the #1 cause of 401s ---
if (!MONGODB_URI) {
  console.error("Missing MONGODB_URI in .env");
  process.exit(1);
}
if (!CLIENT_URL) {
  console.error("Missing CLIENT_URL in .env — must be the Next.js origin, e.g. http://localhost:3000");
  process.exit(1);
}

const client = new MongoClient(MONGODB_URI);

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

app.use(cors({ origin: CLIENT_URL }));
app.use(express.json());

const mongoClient = await connectToMongoDB();
const db = mongoClient.db("booknook");
const booksCollection = db.collection("books");
const borrowsCollection = db.collection("borrows");

// Create JWKS once at startup, not on every request
const JWKS = createRemoteJWKSet(new URL(`${CLIENT_URL}/api/auth/jwks`));

function normalizeEmail(email) {
  return typeof email === "string" ? email.trim().toLowerCase() : "";
}

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
    const { payload } = await jwtVerify(token, JWKS);
    req.user = {
      id: payload.sub,
      email: normalizeEmail(payload.email),
    };
    next();
  } catch (error) {
    console.error("JWT Verification Error:", error.message);
    return res.status(401).send({ message: "Unauthorized: Token expired or invalid!" });
  }
};

// ---------------- Books ----------------

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

app.get("/featured-books", async (req, res) => {
  try {
    const result = await booksCollection.find().sort({ createdAt: -1 }).limit(6).toArray();
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch featured books", error: error.message });
  }
});

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

app.post("/books", verifyToken, async (req, res) => {
  try {
    const { title, author, category, description, image, totalCopies, userName } = req.body;

    const copies = parseInt(totalCopies) || 1;
    const newBook = {
      title,
      author,
      category,
      description,
      image,
      totalCopies: copies,
      availableCopies: copies,
      // Take owner from the verified token, not the client body
      userEmail: req.user.email || normalizeEmail(req.body.userEmail),
      userName: userName || "",
      createdAt: new Date(),
    };

    const result = await booksCollection.insertOne(newBook);
    res.status(201).send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to add book", error: error.message });
  }
});

app.patch("/books/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).send({ message: "Invalid Book ID format" });
    }

    const book = await booksCollection.findOne({ _id: new ObjectId(id) });
    if (!book) {
      return res.status(404).send({ message: "Book not found" });
    }

    // Ownership check: only the owner can edit (skip if legacy book has no owner)
    if (book.userEmail && normalizeEmail(book.userEmail) !== req.user.email) {
      return res.status(403).send({ message: "Forbidden: You do not own this book" });
    }

    // Whitelist fields — don't let client overwrite _id, createdAt, copies, owner, etc.
    const allowed = ["title", "author", "category", "description", "image"];
    const updatedData = {};
    for (const field of allowed) {
      if (req.body[field] !== undefined) {
        updatedData[field] = req.body[field];
      }
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

app.delete("/books/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).send({ message: "Invalid Book ID format" });
    }

    const book = await booksCollection.findOne({ _id: new ObjectId(id) });
    if (!book) {
      return res.status(404).send({ message: "Book not found" });
    }

    if (book.userEmail && normalizeEmail(book.userEmail) !== req.user.email) {
      return res.status(403).send({ message: "Forbidden: You do not own this book" });
    }

    const result = await booksCollection.deleteOne({ _id: new ObjectId(id) });
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to delete book", error: error.message });
  }
});

// ---------------- Borrows ----------------

app.post("/borrows", verifyToken, async (req, res) => {
  try {
    const { bookId } = req.body;
    const userEmail = req.user.email;

    if (!ObjectId.isValid(bookId)) {
      return res.status(400).send({ message: "Invalid Book ID" });
    }

    const existingBorrow = await borrowsCollection.findOne({
      bookId: new ObjectId(bookId),
      userEmail,
    });

    if (existingBorrow) {
      return res.status(400).send({ message: "You have already borrowed this book and haven't returned it yet!" });
    }

    const book = await booksCollection.findOne({ _id: new ObjectId(bookId) });
    if (!book) {
      return res.status(404).send({ message: "Book not found!" });
    }

    if (book.availableCopies <= 0) {
      return res.status(400).send({ message: "Sorry, this book is currently out of stock / Not Available." });
    }

    // Take title/image from the real book doc, not from client body
    const borrowRecord = {
      bookId: new ObjectId(bookId),
      bookTitle: book.title,
      bookImage: book.image,
      userEmail,
      borrowDate: new Date(),
      returnDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    };

    const result = await borrowsCollection.insertOne(borrowRecord);

    await booksCollection.updateOne(
      { _id: new ObjectId(bookId) },
      { $inc: { availableCopies: -1 } }
    );

    res.status(201).send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to borrow book", error: error.message });
  }
});

app.get("/borrows", verifyToken, async (req, res) => {
  try {
    const result = await borrowsCollection.find({ userEmail: req.user.email }).toArray();
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch borrowed books", error: error.message });
  }
});

app.delete("/borrows/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).send({ message: "Invalid Borrow Record ID format" });
    }

    const borrowRecord = await borrowsCollection.findOne({ _id: new ObjectId(id) });
    if (!borrowRecord) {
      return res.status(404).send({ message: "Borrow record not found!" });
    }

    // Only the borrower can return their own borrow
    if (normalizeEmail(borrowRecord.userEmail) !== req.user.email) {
      return res.status(403).send({ message: "Forbidden: This borrow does not belong to you" });
    }

    const result = await borrowsCollection.deleteOne({ _id: new ObjectId(id) });

    await booksCollection.updateOne(
      { _id: borrowRecord.bookId },
      { $inc: { availableCopies: 1 } }
    );

    res.send(result);
  } catch (error) {
    res.status(500).send({ message: "Failed to return book", error: error.message });
  }
});

app.get("/", (req, res) => {
  res.send({ message: "BookNook Server is running fine!" });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

export default app;