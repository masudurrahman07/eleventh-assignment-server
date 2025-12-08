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

// ====================USER=====================

// Get user profile by email
app.get('/users/:email', verifyToken, async (req, res) => {
  try {
    const email = req.params.email;
    const user = await usersCollection.findOne({ email });
    if (!user) return res.status(404).send({ message: "User not found" });

    // Exclude password from response
    const { password, ...userData } = user;
    res.send(userData);
  } catch (err) {
    console.error("GET /users/:email error:", err);
    res.status(500).send({ message: "Failed to fetch user profile" });
  }
});

app.put('/users/:email', verifyToken, async (req, res) => {
  try {
    const email = req.params.email;
    const updateData = req.body;
    await usersCollection.updateOne({ email }, { $set: updateData });
    res.send({ message: 'Profile updated' });
  } catch (err) {
    res.status(500).send({ message: 'Failed to update profile' });
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
    console.error("GET /meals error:", err);
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

    // Find meals created by this chef
    const chefMeals = await mealsCollection.find({ userEmail: chefEmail }).toArray();
    const chefMealIds = chefMeals.map(meal => String(meal._id));

    // Find orders that match chefMealIds
    const orders = await ordersCollection.find({ foodId: { $in: chefMealIds } }).toArray();

    res.send(orders);
  } catch (err) {
    console.error("GET /orders/chef/:email error:", err);
    res.status(500).send({ message: "Failed to fetch chef orders" });
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
    console.error("GET /reviews/:mealId error:", err);
    res.status(500).send({ message: "Server error" });
  }
});
app.post('/reviews', verifyToken, async (req, res) => {
  try {
    const { foodId, reviewerName, reviewerImage, rating, comment } = req.body;
    if (!foodId || !reviewerName || !rating || !comment)
      return res.status(400).send({ message: "All fields are required" });

    const newReview = {
      foodId: String(foodId),
      reviewerName,
      reviewerImage: reviewerImage || "https://i.ibb.co/0s3pdnc/default-user.png",
      rating,
      comment,
      reviewerEmail: req.user.email, // <-- added
      date: new Date().toISOString(),
    };

    const result = await reviewsCollection.insertOne(newReview);
    res.send({ ...newReview, _id: result.insertedId });
  } catch (err) {
    console.error('POST /reviews error:', err);
    res.status(500).send({ message: "Server error" });
  }
});


// Get all reviews of the logged-in user
app.get('/reviews/my', verifyToken, async (req, res) => {
  try {
    const userEmail = req.user.email;
    const reviews = await reviewsCollection.find({ reviewerEmail: userEmail }).sort({ date: -1 }).toArray();
    res.send(reviews);
  } catch (err) {
    console.error("GET /reviews/my error:", err);
    res.status(500).send({ message: "Failed to fetch your reviews" });
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

// Update a request's status (Admin only)
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

    const collection = client.db('requests-db').collection('requests');

    const result = await collection.findOneAndUpdate(
      { _id: new ObjectId(id) },
      { $set: { requestStatus } },
      { returnDocument: 'after' } // returns updated document
    );

    if (!result.value) return res.status(404).send({ message: "Request not found" });

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
    if (!foodId || !price || !quantity || !userAddress)
      return res.status(400).send({ message: "All fields are required" });

    // Fetch the meal info to get chefName and chefId
    const meal = await mealsCollection.findOne({ _id: new ObjectId(foodId) });
    if (!meal) return res.status(404).send({ message: "Meal not found" });

    const orderEntry = {
      foodId,
      mealName: meal.foodName,      // Use foodName from meals collection
      price,
      quantity,
      chefId: meal.chefId,          // chefId from meals
      chefName: meal.chefName,      // chefName from meals
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
        if (!order.chefName || !order.chefId) {
          let meal;

          // Only convert to ObjectId if valid
          if (ObjectId.isValid(order.foodId)) {
            meal = await mealsCollection.findOne({ _id: new ObjectId(order.foodId) });
          } else {
            // fallback: maybe _id is stored as string
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
