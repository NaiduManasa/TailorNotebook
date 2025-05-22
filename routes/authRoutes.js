const express = require('express');
const bcrypt = require('bcrypt');
const User = require('../models/User');
const Customer = require('../models/Customer');
const Order = require('../models/Order');

const router = express.Router();

// Middleware to check login
function isAuthenticated(req, res, next) {
  if (req.session.userId) {
    return next();
  } else {
    res.status(401).json({ error: 'Not logged in' });
  }
}

// Signup
router.post('/signup', async (req, res) => {
  const { username, password } = req.body;

  try {
    const hash = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hash });
    await newUser.save();
    req.session.userId = newUser._id;
    res.json({ message: 'Signup successful' });
  } catch (err) {
    res.status(400).json({ error: 'User already exists or error saving user' });
  }
});

// Login
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });
  if (!user) return res.status(401).json({ error: 'User not found' });

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) return res.status(401).json({ error: 'Wrong password' });

  req.session.userId = user._id;
  res.json({ message: 'Login successful' });
});

// Logout
router.post('/logout', (req, res) => {
  req.session.destroy();
  res.json({ message: 'Logged out' });
});

// Get customers with orders
router.get('/customers', isAuthenticated, async (req, res) => {
  try {
    const customers = await Customer.find({ userId: req.session.userId }).lean();
    const customerIds = customers.map(c => c._id);

    const orders = await Order.find({ customerId: { $in: customerIds } }).lean();

    const customersWithOrders = customers.map(customer => {
      customer.orders = orders.filter(order => order.customerId.toString() === customer._id.toString());
      return customer;
    });

    res.json(customersWithOrders);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch customers and orders' });
  }
});

module.exports = router;

