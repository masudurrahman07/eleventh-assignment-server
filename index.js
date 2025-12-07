// ==================== IMPORTS ====================
const express = require('express');
const cors = require('cors');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const stripe = require('stripe')(process.env.STRIPE_SECRET);

// ==================== CONFIG ====================
const app = express();
app.use(cors({ origin: '*' })); // allow frontend requests
app.use(express.json());

const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';
const uri = process.env.MONGO_URI;

if (!uri) {
  console.error("❌ ERROR: MONGO_URI is missing in .env");
  process.exit(1);
}

// ==================== MONGO SETUP ====================
let ordersCollection, mealsCollection, reviewsCollection, favoritesCollection, usersCollection;

async function start() {
  try {
    const client = new MongoClient(uri);
    await client.connect();
    console.log("✅ MongoDB connected");

    mealsCollection = client.db('meals-db').collection('meals');
    reviewsCollection = client.db('reviews-db').collection('reviews');
    favoritesCollection = client.db('favorites-db').collection('favorites');
    usersCollection = client.db('users-db').collection('users');
    ordersCollection = client.db('orders-db').collection('order_collection');
  } catch (err) {
    console.error("❌ MongoDB Connection Error:", err.message);
    process.exit(1);
  }
}
start();

// ==================== ROOT ====================
app.get('/', (req, res) => {
  res.send("🚀 Server is running successfully!");
});

// ==================== JWT MIDDLEWARE ====================
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).send({ message: "Unauthorized: No token" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).send({ message: "Unauthorized: Token missing" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.error("JWT verification error:", err);
    return res.status(401).send({ message: "Invalid token" });
  }
}

// ==================== AUTH ====================

// Register
app.post('/auth/register', async (req, res) => {
  try {
    const { name, email, password, profileImage, address } = req.body;
    if (!name || !email || !password || !profileImage || !address)
      return res.status(400).send({ message: "All fields are required" });

    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) return res.status(400).send({ message: "Email already registered" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { name, email, password: hashedPassword, profileImage, address };
    const result = await usersCollection.insertOne(newUser);

    const token = jwt.sign({ email, id: result.insertedId }, JWT_SECRET, { expiresIn: "7d" });
    res.send({ user: { ...newUser, _id: result.insertedId, password: undefined }, token });
  } catch (err) {
    console.error("Register Error:", err);
    res.status(500).send({ message: "Server error" });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).send({ message: "Email and password required" });

    const user = await usersCollection.findOne({ email });
    if (!user) return res.status(400).send({ message: "Invalid credentials" });

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(400).send({ message: "Invalid credentials" });

    const token = jwt.sign({ email, id: user._id }, JWT_SECRET, { expiresIn: "7d" });
    res.send({ user: { ...user, password: undefined }, token });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).send({ message: "Server error" });
  }
});

// ==================== MEALS ====================
app.get('/meals', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const meals = await mealsCollection.find().skip(skip).limit(limit).toArray();
    const total = await mealsCollection.countDocuments();

    res.send({ total, meals });
  } catch (err) {
    res.status(500).send({ message: "Server error" });
  }
});

app.get('/meals/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const query = ObjectId.isValid(id) ? { _id: new ObjectId(id) } : { _id: id };
    const meal = await mealsCollection.findOne(query);
    if (!meal) return res.status(404).send({ message: "Meal not found" });
    res.send(meal);
  } catch (err) {
    res.status(500).send({ message: "Server error" });
  }
});

// ==================== REVIEWS ====================
app.get('/reviews', async (req, res) => {
  try {
    const { foodId } = req.query;
    const filter = foodId ? { foodId } : {};
    const reviews = await reviewsCollection.find(filter).toArray();
    res.send(reviews);
  } catch (err) {
    console.error('GET /reviews error:', err);
    res.status(500).send({ message: "Server error" });
  }
});

app.get('/reviews/:mealId', async (req, res) => {
  try {
    const { mealId } = req.params;
    const mealIdStr = String(mealId);
    const globalSix = await reviewsCollection.find({}).sort({ date: -1 }).limit(6).toArray();
    const mealReviews = await reviewsCollection.find({ foodId: mealIdStr }).sort({ date: -1 }).toArray();

    const existingIds = new Set(globalSix.map(r => String(r._id)));
    const merged = [...globalSix];
    for (const r of mealReviews) if (!existingIds.has(String(r._id))) merged.push(r);

    res.send(merged);
  } catch (err) {
    console.error("Error fetching /reviews/:mealId:", err);
    res.status(500).send({ message: "Server error" });
  }
});

app.post('/reviews', async (req, res) => {
  try {
    const { foodId, reviewerName, reviewerImage, rating, comment } = req.body;
    if (!foodId || !reviewerName || !rating || !comment) return res.status(400).send({ message: "All fields are required" });

    const newReview = {
      foodId: String(foodId),
      reviewerName,
      reviewerImage: reviewerImage || "https://i.ibb.co/0s3pdnc/default-user.png",
      rating,
      comment,
      date: new Date().toISOString(),
    };

    const result = await reviewsCollection.insertOne(newReview);
    res.send({ ...newReview, _id: result.insertedId });
  } catch (err) {
    console.error('POST /reviews error:', err);
    res.status(500).send({ message: "Server error" });
  }
});

// ==================== FAVORITES ====================
app.get('/favorites', verifyToken, async (req, res) => {
  try {
    const favorites = await favoritesCollection.find({ userEmail: req.user.email }).toArray();
    res.send(favorites);
  } catch (err) {
    console.error("GET /favorites error:", err);
    res.status(500).send({ message: "Server error" });
  }
});

app.post('/favorites', verifyToken, async (req, res) => {
  try {
    const { mealId } = req.body;
    if (!mealId) return res.status(400).send({ message: "Meal ID is required" });

    const mealQuery = ObjectId.isValid(mealId) ? { _id: new ObjectId(mealId) } : { _id: mealId };
    const meal = await mealsCollection.findOne(mealQuery);
    if (!meal) return res.status(404).send({ message: "Meal not found" });

    const existing = await favoritesCollection.findOne({ userEmail: req.user.email, mealId });
    if (existing) return res.status(400).send({ message: "Already in favorites" });

    const favoriteEntry = {
      userEmail: req.user.email,
      mealId,
      mealName: meal.foodName || "N/A",
      chefId: meal.chefId || "N/A",
      chefName: meal.chefName || "N/A",
      price: meal.price || 0,
      addedTime: new Date().toISOString(),
    };

    await favoritesCollection.insertOne(favoriteEntry);
    res.send({ message: "Added to favorites", favorite: favoriteEntry });
  } catch (err) {
    console.error("POST /favorites error:", err);
    res.status(500).send({ message: "Server error" });
  }
});

// ==================== ORDERS ====================
app.post('/orders', verifyToken, async (req, res) => {
  try {
    const { foodId, mealName, price, quantity, chefId, userAddress, orderStatus, paymentStatus } = req.body;

    if (!foodId || !mealName || !price || !quantity || !chefId || !userAddress)
      return res.status(400).send({ message: "All fields are required" });

    const orderEntry = {
      foodId,
      mealName,
      price,
      quantity,
      chefId,
      userEmail: req.user.email,
      userAddress,
      orderStatus: orderStatus || "pending",
      paymentStatus: paymentStatus || "Pending",
      orderTime: new Date().toISOString(),
    };

    const result = await ordersCollection.insertOne(orderEntry);
    res.send({ message: "Order placed successfully!", order: { ...orderEntry, _id: result.insertedId } });
  } catch (err) {
    console.error("POST /orders error:", err);
    res.status(500).send({ message: "Server error" });
  }
});

// ==================== STRIPE PAYMENT ====================
app.post('/create-payment-intent', verifyToken, async (req, res) => {
  try {
    const { amount } = req.body;
    if (!amount) return res.status(400).send({ message: "Amount is required" });

    const paymentIntent = await stripe.paymentIntents.create({
      amount,
      currency: 'usd',
      automatic_payment_methods: { enabled: true },
    });

    res.send({ clientSecret: paymentIntent.client_secret });
  } catch (err) {
    console.error('Payment Intent Error:', err);
    res.status(500).send({ message: 'Failed to create payment intent' });
  }
});

// ==================== SERVER START ====================
app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
