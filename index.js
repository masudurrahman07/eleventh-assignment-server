// ==================== IMPORTS ====================
const express = require('express');
const cors = require('cors');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const stripe = require('stripe')(process.env.STRIPE_SECRET);
const multer = require('multer');
const FormData = require('form-data');
const fetch = require('node-fetch');
const axios = require('axios');

// ==================== CONFIG ====================
const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());


const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';
const uri = process.env.MONGO_URI;

if (!uri) {
  console.error("❌ ERROR: MONGO_URI is missing in .env");
  process.exit(1);
}

// ==================== MONGO SETUP ====================
let client;
let ordersCollection, mealsCollection, reviewsCollection, favoritesCollection, usersCollection;

async function start() {
  try {
    client = new MongoClient(uri);
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
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    console.error("JWT verification error:", err);
    return res.status(401).send({ message: "Invalid token" });
  }
}



// ==================== AUTH ====================
app.post('/auth/register', async (req, res) => {
  try {
    const { name, email, password, profileImage, address } = req.body;

    if (!name || !email || !password || !profileImage || !address)
      return res.status(400).send({ message: "All fields are required" });

    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) return res.status(400).send({ message: "Email already registered" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = { 
      name,
      email,
      password: hashedPassword,
      profileImage,
      address,

      // 🔥 DEFAULTS ADDED
      role: "user",
      status: "active",
      chefId: null
    };

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


// ==================== IMAGE UPLOAD ENDPOINT ====================
const upload = multer(); // memory storage


app.post('/upload', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: "Image file is required" });
    }

    const apiKey = process.env.VITE_IMGBB_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ message: "ImgBB API key not set in backend .env" });
    }

    // Convert image to base64
    const base64Image = req.file.buffer.toString('base64');

    // Send POST request to ImgBB
    const response = await axios.post(
      `https://api.imgbb.com/1/upload?key=${apiKey}`,
      new URLSearchParams({ image: base64Image }).toString(),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      }
    );

    const data = response.data;

    if (!data.success) {
      console.error("ImgBB upload failed:", data);
      return res.status(500).json({ message: "ImgBB upload failed", details: data });
    }

    res.json({ url: data.data.url });

  } catch (err) {
    console.error("POST /upload error:", err.message);
    res.status(500).json({ message: "Image upload failed", error: err.message });
  }
});


// =======================USERS============================

// Get a single user by email
app.get('/users/:email', verifyToken, async (req, res) => {
  try {
    const email = req.params.email;

    const user = await usersCollection.findOne({ email }, { projection: { password: 0 } });
    if (!user) return res.status(404).send({ message: "User not found" });

    res.send(user);
  } catch (err) {
    console.error("GET /users/:email error:", err);
    res.status(500).send({ message: "Failed to fetch user" });
  }
});


// ==================== MARK USER AS FRAUD ====================

app.patch('/users/:id/fraud', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    // Find the user first
    const user = await usersCollection.findOne({ _id: new ObjectId(id) });
    if (!user) return res.status(404).send({ message: "User not found" });

    if (user.role === "admin") {
      return res.status(403).send({ message: "Cannot mark admin as fraud" });
    }

    // Update the user's status
    const updateResult = await usersCollection.findOneAndUpdate(
      { _id: new ObjectId(id) },
      { $set: { status: "fraud" } },
      { returnDocument: "after" } // return the updated document
    );

    res.send(updateResult.value); // frontend expects the updated user object
  } catch (err) {
    console.error("PATCH /users/:id/fraud error:", err);
    res.status(500).send({ message: "Server error" });
  }
});





// ==================== MEALS ====================

// Create a meal (chef only)
app.post('/meals', verifyToken, async (req, res) => {
  try {
    const {
      foodName,
      chefName,
      foodImage,
      price,
      rating,
      ingredients,
      estimatedDeliveryTime,
      chefExperience,
    } = req.body;

    if (!foodName || !chefName || !foodImage || !price || !ingredients || !estimatedDeliveryTime || !chefExperience) {
      return res.status(400).send({ message: "All fields are required" });
    }

    // Get the logged-in user
    const user = await usersCollection.findOne({ email: req.user.email });
    if (!user) return res.status(404).send({ message: "User not found" });

    if (user.status === "fraud" && user.role === "chef") {
      return res.status(403).send({ message: "Fraud users cannot create meals" });
    }

    if (user.role !== "chef") {
      return res.status(403).send({ message: "Only chefs can create meals" });
    }

    const meal = {
      foodName,
      chefName,
      foodImage,
      price: parseFloat(price),
      rating: parseFloat(rating) || 0, // Ensure rating is saved
      ingredients: Array.isArray(ingredients)
        ? ingredients
        : ingredients.split(',').map(i => i.trim()),
      estimatedDeliveryTime,
      chefExperience,
      chefId: user.chefId,
      userEmail: user.email,
      createdAt: new Date().toISOString(),
    };

    const result = await mealsCollection.insertOne(meal);
    res.send({ ...meal, _id: result.insertedId });

  } catch (err) {
    console.error("POST /meals error:", err);
    res.status(500).send({ message: "Failed to create meal" });
  }
});
// ==================== GET ALL MEALS (REAL PAGINATION) ====================
app.get('/meals', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const total = await mealsCollection.countDocuments();
    const meals = await mealsCollection
      .find()
      .sort({ createdAt: -1 }) // NEW: always newest first
      .skip(skip)
      .limit(limit)
      .toArray();

    res.send({ total, meals });
  } catch (err) {
    console.error("GET /meals error:", err);
    res.status(500).send({ message: "Server error" });
  }
});

// Get meal by ID
app.get('/meals/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const query = ObjectId.isValid(id) ? { _id: new ObjectId(id) } : { _id: id };
    const meal = await mealsCollection.findOne(query);
    if (!meal) return res.status(404).send({ message: "Meal not found" });
    res.send(meal);
  } catch (err) {
    console.error("GET /meals/:id error:", err);
    res.status(500).send({ message: "Server error" });
  }
});

// Get all meals created by a specific chef
app.get('/meals/chef/:email', verifyToken, async (req, res) => {
  try {
    const email = req.params.email;
    const meals = await mealsCollection.find({ userEmail: email }).toArray();
    res.send(meals);
  } catch (err) {
    console.error("GET /meals/chef/:email error:", err);
    res.status(500).send({ message: "Server error" });
  }
});

// Get all orders assigned to a specific chef
app.get('/orders/chef/:email', verifyToken, async (req, res) => {
  try {
    const chefEmail = req.params.email;
    const chefMeals = await mealsCollection.find({ userEmail: chefEmail }).toArray();
    const chefMealIds = chefMeals.map(meal => String(meal._id));
    const orders = await ordersCollection.find({ foodId: { $in: chefMealIds } }).toArray();
    res.send(orders);
  } catch (err) {
    console.error("GET /orders/chef/:email error:", err);
    res.status(500).send({ message: "Failed to fetch chef orders" });
  }
});

// ==================== DELETE A MEAL ====================
app.delete('/meals/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid meal ID" });

    const meal = await mealsCollection.findOne({ _id: new ObjectId(id) });
    if (!meal) return res.status(404).send({ message: "Meal not found" });

    if (meal.userEmail !== req.user.email) {
      return res.status(403).send({ message: "Forbidden: You can only delete your own meals" });
    }

    await mealsCollection.deleteOne({ _id: new ObjectId(id) });
    res.send({ message: "Meal deleted successfully" });
  } catch (err) {
    console.error("DELETE /meals/:id error:", err);
    res.status(500).send({ message: "Failed to delete meal" });
  }
});

// ==================== UPDATE A MEAL ====================
app.put('/meals/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = req.body;

    if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid meal ID" });

    const meal = await mealsCollection.findOne({ _id: new ObjectId(id) });
    if (!meal) return res.status(404).send({ message: "Meal not found" });

    if (meal.userEmail !== req.user.email) {
      return res.status(403).send({ message: "Forbidden: You can only update your own meals" });
    }

    // Ensure ingredients is always an array
    if (updateData.ingredients && !Array.isArray(updateData.ingredients)) {
      updateData.ingredients = updateData.ingredients.split(',').map(i => i.trim());
    }

    // Ensure rating is numeric if present
    if (updateData.rating !== undefined) {
      updateData.rating = parseFloat(updateData.rating) || 0;
    }

    await mealsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updateData }
    );

    const updatedMeal = await mealsCollection.findOne({ _id: new ObjectId(id) });
    res.send(updatedMeal);
  } catch (err) {
    console.error("PUT /meals/:id error:", err);
    res.status(500).send({ message: "Failed to update meal" });
  }
});

// ==================== UPDATE ORDER STATUS ====================
app.patch('/orders/:id/status', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!status) return res.status(400).send({ message: "Status is required" });
    if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid order ID" });

    // Find the order
    const order = await ordersCollection.findOne({ _id: new ObjectId(id) });
    if (!order) return res.status(404).send({ message: "Order not found" });

    // Only the chef who owns the order's meal can update
    const meal = await mealsCollection.findOne({ _id: new ObjectId(order.foodId) });
    if (!meal) return res.status(404).send({ message: "Associated meal not found" });

    if (meal.userEmail !== req.user.email) {
      return res.status(403).send({ message: "Forbidden: You can only update your own orders" });
    }

    // Update the order status
    await ordersCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { orderStatus: status } }
    );

    const updatedOrder = await ordersCollection.findOne({ _id: new ObjectId(id) });
    res.send(updatedOrder);

  } catch (err) {
    console.error("PATCH /orders/:id/status error:", err);
    res.status(500).send({ message: "Failed to update order status" });
  }
});

// ==================== REVIEWS ====================

// 1️⃣ Create a review
app.post('/reviews', verifyToken, async (req, res) => {
  try {
    const { foodId, reviewerName, reviewerImage, rating, comment } = req.body;
    if (!foodId || !reviewerName || !rating || !comment)
      return res.status(400).json({ message: "All fields are required" });

    const newReview = {
      foodId: String(foodId),
      reviewerName,
      reviewerImage: reviewerImage || "https://i.ibb.co/0s3pdnc/default-user.png",
      rating,
      comment,
      reviewerEmail: req.user.email.toLowerCase(), // lowercase email
      date: new Date().toISOString(),
    };

    const result = await reviewsCollection.insertOne(newReview);
    res.json({ ...newReview, _id: result.insertedId });
  } catch (err) {
    console.error('POST /reviews error:', err);
    res.status(500).json({ message: "Server error" });
  }
});

// 2️⃣ Get logged-in user's reviews
// 2️⃣ Get logged-in user's reviews (with meal names)
app.get('/reviews/my', verifyToken, async (req, res) => {
  try {
    const userEmail = req.user.email.toLowerCase();
    const reviews = await reviewsCollection.find({ reviewerEmail: userEmail })
      .sort({ date: -1 })
      .toArray();

    // If no reviews, return empty array
    if (reviews.length === 0) return res.json([]);

    // Fetch all meals that match the foodIds in the reviews
    const foodIds = reviews.map(r => r.foodId);
    const meals = await mealsCollection.find({ _id: { $in: foodIds.map(id => ObjectId.isValid(id) ? new ObjectId(id) : id) } }).toArray();

    // Map meals by id for quick lookup
    const mealMap = {};
    meals.forEach(meal => {
      mealMap[String(meal._id)] = meal.foodName;
    });

    // Attach mealName to each review
    const reviewsWithMealName = reviews.map(r => ({
      ...r,
      mealName: mealMap[r.foodId] || 'Unknown Meal',
      _id: String(r._id),
    }));

    res.json(reviewsWithMealName);
  } catch (err) {
    console.error("GET /reviews/my error:", err);
    res.status(500).json({ message: "Failed to fetch your reviews" });
  }
});


// 3️⃣ Delete a review
app.delete('/reviews/:reviewId', verifyToken, async (req, res) => {
  try {
    const { reviewId } = req.params;
    const userEmail = req.user.email.toLowerCase();

    const result = await reviewsCollection.deleteOne({
      _id: new ObjectId(reviewId),
      reviewerEmail: userEmail,
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "Review not found or you don't have permission" });
    }

    res.json({ message: "Review deleted successfully" });
  } catch (err) {
    console.error("DELETE /reviews/:reviewId error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// 4️⃣ Update a review
// Update review — PATCH /reviews/:reviewId
app.patch('/reviews/:reviewId', verifyToken, async (req, res) => {
  try {
    const { reviewId } = req.params;
    const { rating, comment } = req.body;

    if (rating === undefined && comment === undefined) {
      return res.status(400).json({ message: "Nothing to update" });
    }

    let objectId;
    try {
      objectId = new ObjectId(reviewId);
    } catch {
      return res.status(400).json({ message: "Invalid review ID" });
    }

    // Normalize email
    const userEmail = req.user.email.toLowerCase();

    // Prepare fields to update
    const updateFields = {};
    if (rating !== undefined) updateFields.rating = rating;
    if (comment !== undefined) updateFields.comment = comment;
    updateFields.date = new Date().toISOString();

    // Find review first
    const existingReview = await reviewsCollection.findOne({ _id: objectId });
    if (!existingReview) {
      return res.status(404).json({ message: "Review not found" });
    }

    // Check if logged-in user is the owner
    if (existingReview.reviewerEmail.toLowerCase() !== userEmail) {
      return res.status(403).json({ message: "You do not have permission to update this review" });
    }

    // Update the review
    const result = await reviewsCollection.findOneAndUpdate(
      { _id: objectId },
      { $set: updateFields },
      { returnDocument: "after" }
    );

    res.status(200).json(result.value);

  } catch (err) {
    console.error("PATCH /reviews/:reviewId error:", err);
    res.status(500).json({ message: "Server error" });
  }
});


// 5️⃣ Get reviews of a meal
app.get('/reviews/meal/:mealId', async (req, res) => {
  try {
    const { mealId } = req.params;
    const mealIdStr = String(mealId);

    const mealReviews = await reviewsCollection.find({ foodId: mealIdStr })
      .sort({ date: -1 })
      .toArray();

    res.json(mealReviews);
  } catch (err) {
    console.error("GET /reviews/meal/:mealId error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// 6️⃣ Get all reviews
app.get('/reviews', async (req, res) => {
  try {
    const { foodId } = req.query;
    const filter = foodId ? { foodId } : {};
    const reviews = await reviewsCollection.find(filter).toArray();
    res.json(reviews);
  } catch (err) {
    console.error('GET /reviews error:', err);
    res.status(500).json({ message: "Server error" });
  }
});

// ==================REQUEST=========================
app.post('/requests', verifyToken, async (req, res) => {
  try {
    const { userName, userEmail, requestType, requestStatus, requestTime } = req.body;
    const reqDoc = {
      userName,
      userEmail,
      requestType,
      requestStatus: requestStatus || 'pending',
      requestTime: requestTime || new Date().toISOString()
    };

    const result = await client.db('requests-db').collection('requests').insertOne(reqDoc);
    res.send({ message: 'Request sent', requestId: result.insertedId });
  } catch (err) {
    console.error('POST /requests error:', err);
    res.status(500).send({ message: 'Failed to send request' });
  }
});

// Get all requests (Admin only)
app.get('/requests', verifyToken, async (req, res) => {
  try {
    // Optional: restrict to admins
    const admin = await usersCollection.findOne({ email: req.user.email });
    if (!admin || admin.role !== "admin") {
      return res.status(403).send({ message: "Forbidden: Admins only" });
    }

    const requests = await client.db('requests-db').collection('requests').find().toArray();
    res.send(requests);
  } catch (err) {
    console.error('GET /requests error:', err);
    res.status(500).send({ message: 'Failed to fetch requests' });
  }
});


// Update a request's status (Admin only) with automatic role update
app.patch('/requests/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { requestStatus } = req.body;

    if (!requestStatus) return res.status(400).send({ message: "requestStatus is required" });

    // Only allow admin
    const admin = await usersCollection.findOne({ email: req.user.email });
    if (!admin || admin.role !== "admin") {
      return res.status(403).send({ message: "Forbidden: Admins only" });
    }

    const requestsCollection = client.db('requests-db').collection('requests');

    // Get the original request
    const reqDoc = await requestsCollection.findOne({ _id: new ObjectId(id) });
    if (!reqDoc) return res.status(404).send({ message: "Request not found" });

    // Update request status
    const result = await requestsCollection.findOneAndUpdate(
      { _id: new ObjectId(id) },
      { $set: { requestStatus } },
      { returnDocument: 'after' }
    );

    // If approved, update the user role
    if (requestStatus === 'approved') {
      if (reqDoc.requestType === 'chef') {
        const chefId = `chef-${Math.floor(1000 + Math.random() * 9000)}`;
        await usersCollection.updateOne(
          { email: reqDoc.userEmail },
          { $set: { role: 'chef', chefId } }
        );
      } else if (reqDoc.requestType === 'admin') {
        await usersCollection.updateOne(
          { email: reqDoc.userEmail },
          { $set: { role: 'admin' } }
        );
      }
    }

    res.send(result.value);

  } catch (err) {
    console.error('PATCH /requests/:id error:', err);
    res.status(500).send({ message: 'Failed to update request' });
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


// GET alias (for compatibility) -> return logged-in user's favorites
app.get('/favorites/my', verifyToken, async (req, res) => {
  try {
    const favorites = await favoritesCollection.find({ userEmail: req.user.email }).toArray();
    res.send(favorites);
  } catch (err) {
    console.error("GET /favorites/my error:", err);
    res.status(500).send({ message: "Failed to fetch your favorites" });
  }
});

// DELETE a favorite by its _id
app.delete('/favorites/:id', verifyToken, async (req, res) => {
  try {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) return res.status(400).send({ message: "Invalid id" });

    // ensure the user owns the favorite before deleting
    const existing = await favoritesCollection.findOne({ _id: new ObjectId(id) });
    if (!existing) return res.status(404).send({ message: "Favorite not found" });
    if (existing.userEmail !== req.user.email) return res.status(403).send({ message: "Forbidden" });

    await favoritesCollection.deleteOne({ _id: new ObjectId(id) });
    res.send({ message: "Favorite removed" });
  } catch (err) {
    console.error("DELETE /favorites/:id error:", err);
    res.status(500).send({ message: "Failed to delete favorite" });
  }
});


// ==================== ORDERS ====================
app.post('/orders', verifyToken, async (req, res) => {
  try {
    const { foodId, price, quantity, userAddress, orderStatus, paymentStatus } = req.body;

    if (!foodId || !price || !quantity || !userAddress) {
      return res.status(400).send({ message: "All fields are required" });
    }

    // Get the logged-in user
    const user = await usersCollection.findOne({ email: req.user.email });
    if (!user) return res.status(404).send({ message: "User not found" });

    if (user.status === "fraud" && user.role === "user") {
      return res.status(403).send({ message: "Fraud users cannot place orders" });
    }

    // Safely fetch the meal info
    let meal;
    if (ObjectId.isValid(foodId)) {
      meal = await mealsCollection.findOne({ _id: new ObjectId(foodId) });
    } else {
      meal = await mealsCollection.findOne({ _id: foodId });
    }

    if (!meal) return res.status(404).send({ message: "Meal not found" });

    const orderEntry = {
      foodId,
      mealName: meal.foodName || "N/A",
      price,
      quantity,
      chefId: meal.chefId || "N/A",
      chefName: meal.chefName || "N/A",
      userEmail: req.user.email,
      userAddress,
      orderStatus: orderStatus || "pending",
      paymentStatus: paymentStatus || "pending",
      orderTime: new Date().toISOString(),
    };

    const result = await ordersCollection.insertOne(orderEntry);
    res.send({ message: "Order placed successfully!", order: { ...orderEntry, _id: result.insertedId } });

  } catch (err) {
    console.error("POST /orders error:", err);
    res.status(500).send({ message: "Server error" });
  }
});


app.get('/orders/my', verifyToken, async (req, res) => {
  try {
    const orders = await ordersCollection.find({ userEmail: req.user.email }).toArray();

    const updatedOrders = await Promise.all(
      orders.map(async (order) => {
        // If chefName or chefId is missing, fetch from meals collection
        if (!order.chefName || !order.chefId) {
          let meal;
          if (ObjectId.isValid(order.foodId)) {
            meal = await mealsCollection.findOne({ _id: new ObjectId(order.foodId) });
          } else {
            meal = await mealsCollection.findOne({ _id: order.foodId });
          }

          if (meal) {
            order.chefName = meal.chefName || "N/A";
            order.chefId = meal.chefId || "N/A";

            // Optional: update DB for future requests
            await ordersCollection.updateOne(
              { _id: order._id },
              { $set: { chefName: order.chefName, chefId: order.chefId } }
            );
          } else {
            order.chefName = "N/A";
            order.chefId = "N/A";
          }
        }
        return order;
      })
    );

    res.send(updatedOrders);

  } catch (err) {
    console.error("GET /orders/my error:", err);
    res.status(500).send({ message: "Failed to fetch your orders" });
  }
});

// ====================== ADMIN =========================

// Admin Dashboard Data
app.get('/admin/dashboard', verifyToken, async (req, res) => {
  try {
    const totalUsers = await usersCollection.countDocuments();
    const pendingOrders = await ordersCollection.countDocuments({ status: "pending" });
    const deliveredOrders = await ordersCollection.countDocuments({ status: "delivered" });

    const admin = await usersCollection.findOne({ email: req.user.email });
    if (!admin) return res.status(404).send({ message: "Admin not found" });

    res.send({
      name: admin.name,
      totalUsers,
      pendingOrders,
      deliveredOrders,
    });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to load admin dashboard" });
  }
});

// Get all users (admin only)
app.get('/users', verifyToken, async (req, res) => {
  try {
    // Optional: allow only admin to access
    const admin = await usersCollection.findOne({ email: req.user.email });
    if (!admin || admin.role !== "admin") {
      return res.status(403).send({ message: "Forbidden: Admins only" });
    }

    const users = await usersCollection.find().project({ password: 0 }).toArray();
    res.send(users);
  } catch (err) {
    console.error("GET /users error:", err);
    res.status(500).send({ message: "Failed to fetch users" });
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

// Update payment status
app.patch('/orders/:id/pay', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { paymentStatus } = req.body;

    if (!paymentStatus) return res.status(400).send({ message: "Payment status required" });

    const result = await ordersCollection.updateOne(
      { _id: new ObjectId(id), userEmail: req.user.email },
      { $set: { paymentStatus } }
    );

    if (result.matchedCount === 0) return res.status(404).send({ message: "Order not found" });

    res.send({ message: "Payment status updated successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to update payment status" });
  }
});


// ==================== SERVER START ====================
app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
