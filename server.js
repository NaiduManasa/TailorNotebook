const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
require('dotenv').config(); // Load environment variables from .env file

const app = express();

// Middleware
app.use(cors()); // Enables Cross-Origin Resource Sharing
app.use(express.json()); // Parses incoming requests with JSON payloads

// Serve static files from the 'public' directory.
// IMPORTANT: Ensure your dashboard.html, login.html, photo.png, and any client-side JS/CSS
// are placed INSIDE a folder named 'public' in the same directory as server.js
app.use(express.static(path.join(__dirname, 'public')));

// Session Setup
app.use(session({
    secret: process.env.SESSION_SECRET || 'my-secret-key', // Use environment variable for secret, fallback for dev
    resave: false, // Don't save session if unmodified
    saveUninitialized: false, // Don't create session until something is stored
    store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }), // Store sessions in MongoDB
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24, // 1 day in milliseconds
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production (requires HTTPS)
        httpOnly: true // Prevents client-side JavaScript from accessing the cookie
    }
}));

// MongoDB Connection
(async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('✅ MongoDB connected');
    } catch (err) {
        console.error('❌ MongoDB connection error:', err);
    }
})();

// Models
// Ensure these paths are correct relative to your server.js
const Customer = require('./models/Customer');
const User = require('./models/User');

// Middleware: Check Authenticated Session
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        return next();
    }
    // If not authenticated, redirect to login page (for browser requests)
    // or send 401 (for API requests)
    if (req.accepts('html')) {
        return res.redirect('/login.html'); // Redirect to login page for browser navigation
    }
    return res.status(401).json({ error: 'Unauthorized. Please login.' });
}

// --- Authentication Routes ---

// 🧾 Signup Route
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: 'Username already taken' });
        }

        const hash = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hash });
        await newUser.save();

        req.session.userId = newUser._id; // Log in the user automatically after signup
        res.status(201).json({ message: 'Signup successful' });
    } catch (err) {
        console.error('Signup error:', err);
        res.status(500).json({ error: 'Signup failed. Please try again.' });
    }
});

// 🔑 Login Route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(401).json({ error: 'User not found' });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ error: 'Invalid password' });

        req.session.userId = user._id;
        res.json({ message: 'Login successful' });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Login failed. Please try again.' });
    }
});

// 🚪 Logout Route
app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).json({ error: 'Failed to log out' });
        }
        res.clearCookie('connect.sid'); // Clear session cookie
        res.json({ message: 'Logged out successfully' });
    });
});

// 👤 Session Check (for client-side routing)
app.get('/api/session', (req, res) => {
    res.json({ loggedIn: !!req.session.userId });
});

// 👤 Logged-in User Info (for debugging/display)
app.get('/api/me', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId).select('-password'); // Exclude password
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json({ user });
    } catch (err) {
        console.error('Error fetching user info:', err);
        res.status(500).json({ error: 'Failed to fetch user info' });
    }
});

// --- Customer Management API Routes (Require Authentication) ---

// ➕ Create Customer
app.post('/api/customers', isAuthenticated, async (req, res) => {
    const { name, phone, gender, shoulder, chest, hip, sleeveLength } = req.body;

    if (!name || !phone || !gender || isNaN(shoulder) || isNaN(chest) || isNaN(hip) || isNaN(sleeveLength)) {
        return res.status(400).json({ error: 'Invalid or missing data' });
    }

    try {
        const newCustomer = new Customer({
            name,
            phone,
            gender,
            shoulder,
            chest,
            hip,
            sleeveLength,
            user: req.session.userId // Link customer to the logged-in user
        });

        await newCustomer.save();
        res.status(201).json({ message: 'Customer added successfully', customer: newCustomer });
    } catch (err) {
        console.error('Error saving customer:', err);
        res.status(500).json({ error: 'Failed to add customer' });
    }
});

// 📄 Get Customers (only logged-in user's data), prioritized by orders
app.get('/api/customers', isAuthenticated, async (req, res) => {
    try {
        const customers = await Customer.aggregate([
            {
                $match: { user: new mongoose.Types.ObjectId(req.session.userId) }
            },
            {
                $addFields: {
                    hasOrders: { $gt: [ { $size: '$orders' }, 0 ] },
                    latestOrderDate: { $max: '$orders.createdAt' } // Get the latest order timestamp
                }
            },
            {
                $sort: {
                    hasOrders: -1,      // Customers with orders first (true > false)
                    latestOrderDate: -1 // Sort by latest order date (newest first)
                }
            },
            {
                $project: {
                    _id: 1,
                    name: 1,
                    phone: 1,
                    gender: 1,
                    shoulder: 1,
                    chest: 1,
                    hip: 1,
                    sleeveLength: 1,
                    orders: 1 // Include the orders array in the response
                }
            }
        ]);
        res.json(customers);
    } catch (err) {
        console.error('Error fetching customers:', err);
        res.status(500).json({ error: 'Failed to fetch customers' });
    }
});

// ✏️ Update Customer (only if owned by logged-in user)
app.put('/api/customers/:id', isAuthenticated, async (req, res) => {
    try {
        const updated = await Customer.findOneAndUpdate(
            { _id: req.params.id, user: req.session.userId }, // Find by ID and user ownership
            req.body, // Update with request body
            { new: true, runValidators: true } // Return the updated document, run Mongoose validators
        );
        if (!updated) return res.status(404).json({ error: 'Customer not found or not authorized' });
        res.json({ message: 'Customer updated successfully', customer: updated });
    } catch (err) {
        console.error('Error updating customer:', err);
        res.status(500).json({ error: 'Update failed' });
    }
});

// ❌ Delete Customer (only if owned by logged-in user)
app.delete('/api/customers/:id', isAuthenticated, async (req, res) => {
    try {
        const deleted = await Customer.findOneAndDelete({
            _id: req.params.id,
            user: req.session.userId
        });
        if (!deleted) return res.status(404).json({ error: 'Customer not found or not authorized' });
        res.json({ message: 'Customer deleted successfully' });
    } catch (err) {
        console.error('Error deleting customer:', err);
        res.status(500).json({ error: 'Delete failed' });
    }
});

// --- Order Management API Routes (Require Authentication) ---

// ➕ Add Order
app.post('/api/customers/:id/order', isAuthenticated, async (req, res) => {
    const { returnDate, note } = req.body;

    if (!returnDate || !note) {
        return res.status(400).json({ error: 'Return date and note are required' });
    }

    try {
        // Find customer by ID and ensure it belongs to the logged-in user
        const customer = await Customer.findOne({ _id: req.params.id, user: req.session.userId });
        if (!customer) return res.status(404).json({ error: 'Customer not found or not authorized' });

        const newOrder = { returnDate, note, status: 'Pending' }; // New order with 'Pending' status
        customer.orders.push(newOrder); // Add the new order to the customer's orders array
        await customer.save(); // Save the updated customer document

        res.status(201).json({ message: 'Order placed successfully', order: newOrder });
    } catch (err) {
        console.error('Error placing order:', err);
        res.status(500).json({ error: 'Failed to place order' });
    }
});

// ✏️ Update Order Status (e.g., Mark Complete)
app.put('/api/customers/:customerId/order/:orderId', isAuthenticated, async (req, res) => {
    const { customerId, orderId } = req.params;
    const { status } = req.body; // Expecting `status` to be sent in the request body

    if (!status) {
        return res.status(400).json({ error: 'Status is required' });
    }

    try {
        const customer = await Customer.findOne({ _id: customerId, user: req.session.userId });
        if (!customer) return res.status(404).json({ error: 'Customer not found or not authorized' });

        // Find the specific order within the customer's orders array
        const order = customer.orders.id(orderId);
        if (!order) return res.status(404).json({ error: 'Order not found' });

        order.status = status; // Update the order status
        await customer.save(); // Save the customer document to persist the order change

        res.json({ message: 'Order status updated successfully', order });
    } catch (err) {
        console.error('Error updating order status:', err);
        res.status(500).json({ error: 'Failed to update order status' });
    }
});

// ❌ Delete Specific Order
app.delete('/api/customers/:customerId/order/:orderId', isAuthenticated, async (req, res) => {
    const { customerId, orderId } = req.params;

    try {
        const customer = await Customer.findOneAndUpdate(
            { _id: customerId, user: req.session.userId }, // Find customer by ID and user ownership
            { $pull: { orders: { _id: orderId } } }, // Use $pull to remove the specific order by its _id
            { new: true } // Return the updated document after the pull operation
        );

        if (!customer) {
            return res.status(404).json({ error: 'Customer not found or not authorized' });
        }

        // It's generally good practice to confirm the item was removed.
        // Mongoose's $pull returns the document *after* the pull, so we can check.
        const orderStillExists = customer.orders.some(order => order._id.toString() === orderId);
        if (orderStillExists) {
            // This case should ideally not happen if $pull worked correctly, but good for robust error handling.
            return res.status(500).json({ error: 'Failed to delete order (order still found after operation)' });
        }

        res.json({ message: 'Order deleted successfully' });
    } catch (err) {
        console.error('Error deleting order:', err);
        res.status(500).json({ error: 'Failed to delete order' });
    }
});

// --- HTML Page Routes (Serve specific HTML files) ---

// Route for the login page
app.get('/login.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Route for the dashboard page, requires authentication
app.get('/dashboard.html', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Redirect root URL to login.html (or dashboard.html if session exists)
app.get('/', (req, res) => {
    if (req.session.userId) {
        res.redirect('/dashboard.html');
    } else {
        res.redirect('/login.html');
    }
});

// 🚀 Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));






// const express = require('express');
// const mongoose = require('mongoose');
// const cors = require('cors');
// const path = require('path');
// const session = require('express-session');
// const MongoStore = require('connect-mongo');
// const bcrypt = require('bcrypt');
// require('dotenv').config();

// const app = express();

// // Middleware
// app.use(cors());
// app.use(express.json());
// app.use(express.static(path.join(__dirname, 'public')));

// // Session Setup
// app.use(session({
//     secret: 'my-secret-key', // Replace with process.env.SECRET in production
//     resave: false,
//     saveUninitialized: false,
//     store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
//     cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1 day
// }));

// // MongoDB Connection
// (async () => {
//     try {
//         await mongoose.connect(process.env.MONGODB_URI);
//         console.log('✅ MongoDB connected');
//     } catch (err) {
//         console.error('❌ MongoDB connection error:', err);
//     }
// })();

// // Models
// const Customer = require('./models/Customer');
// const User = require('./models/User');

// // Middleware: Check Authenticated Session
// function isAuthenticated(req, res, next) {
//     if (req.session.userId) return next();
//     return res.status(401).json({ error: 'Unauthorized. Please login.' });
// }

// // 🧾 Signup Route
// app.post('/signup', async (req, res) => {
//     const { username, password } = req.body;
//     if (!username || !password) {
//         return res.status(400).json({ error: 'Username and password are required' });
//     }

//     try {
//         const existingUser = await User.findOne({ username });
//         if (existingUser) {
//             return res.status(400).json({ error: 'Username already taken' });
//         }

//         const hash = await bcrypt.hash(password, 10);
//         const newUser = new User({ username, password: hash });
//         await newUser.save();

//         req.session.userId = newUser._id;
//         res.json({ message: 'Signup successful' });
//     } catch (err) {
//         console.error('Signup error:', err);
//         res.status(500).json({ error: 'Signup failed. Please try again.' });
//     }
// });

// // 🔑 Login Route
// app.post('/login', async (req, res) => {
//     const { username, password } = req.body;
//     if (!username || !password) {
//         return res.status(400).json({ error: 'Username and password are required' });
//     }

//     try {
//         const user = await User.findOne({ username });
//         if (!user) return res.status(401).json({ error: 'User not found' });

//         const match = await bcrypt.compare(password, user.password);
//         if (!match) return res.status(401).json({ error: 'Invalid password' });

//         req.session.userId = user._id;
//         res.json({ message: 'Login successful' });
//     } catch (err) {
//         console.error('Login error:', err);
//         res.status(500).json({ error: 'Login failed. Please try again.' });
//     }
// });

// // 🚪 Logout Route
// app.post('/logout', (req, res) => {
//     req.session.destroy(() => {
//         res.json({ message: 'Logged out successfully' });
//     });
// });

// // 👤 Session Check
// app.get('/api/session', (req, res) => {
//     res.json({ loggedIn: !!req.session.userId });
// });

// // 👤 Logged-in User Info (for debugging)
// app.get('/api/me', (req, res) => {
//     if (req.session.userId) {
//         res.json({ userId: req.session.userId });
//     } else {
//         res.status(401).json({ error: 'Not logged in' });
//     }
// });

// // ➕ Create Customer
// app.post('/api/customers', isAuthenticated, async (req, res) => {
//     const { name, phone, gender, shoulder, chest, hip, sleeveLength } = req.body;

//     if (!name || !phone || !gender || isNaN(shoulder) || isNaN(chest) || isNaN(hip) || isNaN(sleeveLength)) {
//         return res.status(400).json({ error: 'Invalid or missing data' });
//     }

//     try {
//         const newCustomer = new Customer({
//             name,
//             phone,
//             gender,
//             shoulder,
//             chest,
//             hip,
//             sleeveLength,
//             user: req.session.userId   // 👈 IMPORTANT!
//         });

//         await newCustomer.save();
//         res.status(201).json({ message: 'Customer added successfully' });
//     } catch (err) {
//         console.error('Error saving customer:', err);
//         res.status(500).json({ error: 'Failed to add customer' });
//     }
// });

// // 📄 Get Customers (only logged-in user's data), prioritized by orders
// app.get('/api/customers', isAuthenticated, async (req, res) => {
//     try {
//         const customers = await Customer.aggregate([
//             {
//                 $match: { user: new mongoose.Types.ObjectId(req.session.userId) }
//             },
//             {
//                 $addFields: {
//                     hasOrders: { $gt: [ { $size: '$orders' }, 0 ] },
//                     latestOrderDate: { $max: '$orders.createdAt' } // Get the latest order timestamp
//                 }
//             },
//             {
//                 $sort: {
//                     hasOrders: -1,        // Customers with orders first (true > false)
//                     latestOrderDate: -1   // Sort by latest order date (newest first)
//                 }
//             },
//             {
//                 $project: {
//                     _id: 1,
//                     name: 1,
//                     phone: 1,
//                     gender: 1,
//                     shoulder: 1,
//                     chest: 1,
//                     hip: 1,
//                     sleeveLength: 1,
//                     orders: 1 // Include the orders array if you need it in the response
//                 }
//             }
//         ]);
//         res.json(customers);
//     } catch (err) {
//         console.error('Error fetching customers:', err);
//         res.status(500).json({ error: 'Failed to fetch customers' });
//     }
// });

// // ✏️ Update Customer (only if owned by logged-in user)
// app.put('/api/customers/:id', isAuthenticated, async (req, res) => {
//     try {
//         const updated = await Customer.findOneAndUpdate(
//             { _id: req.params.id, user: req.session.userId },
//             req.body,
//             { new: true }
//         );
//         if (!updated) return res.status(404).json({ error: 'Customer not found' });
//         res.json({ message: 'Customer updated successfully' });
//     } catch (err) {
//         console.error('Error updating customer:', err);
//         res.status(500).json({ error: 'Update failed' });
//     }
// });

// // ❌ Delete Customer (only if owned by logged-in user)
// app.delete('/api/customers/:id', isAuthenticated, async (req, res) => {
//     try {
//         const deleted = await Customer.findOneAndDelete({
//             _id: req.params.id,
//             user: req.session.userId
//         });
//         if (!deleted) return res.status(404).json({ error: 'Customer not found' });
//         res.json({ message: 'Customer deleted successfully' });
//     } catch (err) {
//         console.error('Error deleting customer:', err);
//         res.status(500).json({ error: 'Delete failed' });
//     }
// });

// // 🚀 Add Order Route
// app.post('/api/customers/:id/order', isAuthenticated, async (req, res) => {
//     const { returnDate, note } = req.body;

//     if (!returnDate || !note) {
//         return res.status(400).json({ error: 'Return date and note are required' });
//     }

//     try {
//         const customer = await Customer.findOne({ _id: req.params.id, user: req.session.userId });
//         if (!customer) return res.status(404).json({ error: 'Customer not found' });

//         const newOrder = { returnDate, note, status: 'Pending' }; // New order with 'Pending' status
//         customer.orders.push(newOrder); // Add the new order to the customer
//         await customer.save();

//         res.status(201).json({ message: 'Order placed successfully' });
//     } catch (err) {
//         console.error('Error placing order:', err);
//         res.status(500).json({ error: 'Failed to place order' });
//     }
// });

// // 🚀 Update Order Status Route (Complete Order)
// app.put('/api/customers/:customerId/order/:orderId', isAuthenticated, async (req, res) => {
//     const { customerId, orderId } = req.params;
//     const { status } = req.body;

//     if (!status) {
//         return res.status(400).json({ error: 'Status is required' });
//     }

//     try {
//         const customer = await Customer.findOne({ _id: customerId, user: req.session.userId });
//         if (!customer) return res.status(404).json({ error: 'Customer not found' });

//         const order = customer.orders.id(orderId);
//         if (!order) return res.status(404).json({ error: 'Order not found' });

//         order.status = status; // Update the order status (e.g., "Completed")
//         await customer.save();

//         res.json({ message: 'Order status updated successfully' });
//     } catch (err) {
//         console.error('Error updating order:', err);
//         res.status(500).json({ error: 'Failed to update order status' });
//     }
// });

// // ❌ Delete Specific Order Route
// app.delete('/api/customers/:customerId/order/:orderId', isAuthenticated, async (req, res) => {
//     const { customerId, orderId } = req.params;

//     try {
//         const customer = await Customer.findOneAndUpdate(
//             { _id: customerId, user: req.session.userId },
//             { $pull: { orders: { _id: orderId } } }, // Use $pull to remove the specific order
//             { new: true }
//         );

//         if (!customer) {
//             return res.status(404).json({ error: 'Customer not found' });
//         }

//         // Check if the order was actually removed (optional, for better feedback)
//         const orderExists = customer.orders.some(order => order._id.toString() === orderId);
//         if (orderExists) {
//             return res.status(500).json({ error: 'Failed to delete order' });
//         }

//         res.json({ message: 'Order deleted successfully' });
//     } catch (err) {
//         console.error('Error deleting order:', err);
//         res.status(500).json({ error: 'Failed to delete order' });
//     }
// });







// const customerList = document.getElementById('customerList');
// const searchInput = document.createElement('input');
// searchInput.type = 'search';
// searchInput.placeholder = 'Search customer by name...';
// customerList.parentNode.insertBefore(searchInput, customerList);

// // Container for suggestions dropdown
// const suggestionBox = document.createElement('div');
// suggestionBox.style.border = '1px solid #ccc';
// suggestionBox.style.maxHeight = '150px';
// suggestionBox.style.overflowY = 'auto';
// suggestionBox.style.position = 'absolute';
// suggestionBox.style.backgroundColor = 'white';
// suggestionBox.style.width = searchInput.offsetWidth + 'px';
// suggestionBox.style.zIndex = '1000';
// suggestionBox.style.display = 'none';
// customerList.parentNode.insertBefore(suggestionBox, customerList);

// // Fetch all customers for suggestions
// async function fetchCustomerSuggestions(query) {
//   if (!query) {
//     suggestionBox.style.display = 'none';
//     return [];
//   }
//   try {
//     const res = await fetch('/api/customers');
//     if (!res.ok) throw new Error('Failed to fetch customers');
//     const customers = await res.json();

//     // Filter customers by name matching query (case-insensitive)
//     return customers.filter(cust => cust.name.toLowerCase().includes(query.toLowerCase()));
//   } catch (err) {
//     console.error(err);
//     return [];
//   }
// }

// // Render suggestions dropdown
// function renderSuggestions(customers) {
//   suggestionBox.innerHTML = '';
//   if (customers.length === 0) {
//     suggestionBox.style.display = 'none';
//     return;
//   }
//   customers.forEach(cust => {
//     const div = document.createElement('div');
//     div.textContent = cust.name;
//     div.style.padding = '5px';
//     div.style.cursor = 'pointer';
//     div.addEventListener('click', () => {
//       searchInput.value = cust.name;
//       suggestionBox.style.display = 'none';
//       fetchAndRenderCustomerDetails(cust._id);
//     });
//     suggestionBox.appendChild(div);
//   });
//   suggestionBox.style.display = 'block';
// }

// // Fetch and display full customer details by ID
// async function fetchAndRenderCustomerDetails(customerId) {
//   try {
//     const res = await fetch(`/api/customers`);
//     if (!res.ok) throw new Error('Failed to fetch customer details');
//     const customers = await res.json();
//     const cust = customers.find(c => c._id === customerId);
//     if (!cust) throw new Error('Customer not found');

//     renderCustomerDetails(cust);
//   } catch (err) {
//     customerList.innerHTML = `<p style="color:red;">${err.message}</p>`;
//   }
// }

// // Render full customer details with update/delete forms
// function renderCustomerDetails(customer) {
//   customerList.innerHTML = `
//     <h3>Customer Details</h3>
//     <form id="updateCustomerForm">
//       <label>Name: <input name="name" value="${customer.name}" required /></label><br/>
//       <label>Phone: <input name="phone" value="${customer.phone}" required /></label><br/>
//       <label>Gender: 
//         <select name="gender" required>
//           <option ${customer.gender === 'Male' ? 'selected' : ''}>Male</option>
//           <option ${customer.gender === 'Female' ? 'selected' : ''}>Female</option>
//           <option ${customer.gender === 'Other' ? 'selected' : ''}>Other</option>
//         </select>
//       </label><br/>
//       <label>Shoulder: <input type="number" name="shoulder" value="${customer.shoulder}" required /></label><br/>
//       <label>Chest: <input type="number" name="chest" value="${customer.chest}" required /></label><br/>
//       <label>Hip: <input type="number" name="hip" value="${customer.hip}" required /></label><br/>
//       <label>Sleeve Length: <input type="number" name="sleeveLength" value="${customer.sleeveLength}" required /></label><br/>
//       <button type="submit">Update Customer</button>
//       <button type="button" id="deleteCustomerBtn">Delete Customer</button>
//     </form>

//     <h4>Orders</h4>
//     <div id="ordersList">
//       ${customer.orders.length === 0 ? '<p>No orders.</p>' : ''}
//       ${customer.orders.map(order => `
//         <div data-order-id="${order._id}" style="border:1px solid #ccc; padding:5px; margin-bottom:5px;">
//           <p>Return Date: ${new Date(order.returnDate).toLocaleDateString()}</p>
//           <p>Note: ${order.note}</p>
//           <p>Status: ${order.status}</p>
//           <button class="completeOrderBtn">Mark Complete</button>
//           <button class="deleteOrderBtn">Delete Order</button>
//         </div>
//       `).join('')}
//     </div>
//   `;

//   // Attach update form submit handler
//   const updateForm = document.getElementById('updateCustomerForm');
//   updateForm.addEventListener('submit', async (e) => {
//     e.preventDefault();
//     const formData = new FormData(updateForm);
//     const data = Object.fromEntries(formData.entries());

//     try {
//       const res = await fetch(`/api/customers/${customer._id}`, {
//         method: 'PUT',
//         headers: { 'Content-Type': 'application/json' },
//         body: JSON.stringify(data)
//       });
//       if (!res.ok) throw new Error('Update failed');
//       alert('Customer updated!');
//       // Optionally re-fetch details to refresh UI
//       fetchAndRenderCustomerDetails(customer._id);
//     } catch (err) {
//       alert(err.message);
//     }
//   });

//   // Delete customer button handler
//   document.getElementById('deleteCustomerBtn').addEventListener('click', async () => {
//     if (!confirm('Delete this customer?')) return;
//     try {
//       const res = await fetch(`/api/customers/${customer._id}`, { method: 'DELETE' });
//       if (!res.ok) throw new Error('Delete failed');
//       alert('Customer deleted');
//       customerList.innerHTML = '';
//       searchInput.value = '';
//     } catch (err) {
//       alert(err.message);
//     }
//   });

//   // Attach order buttons handlers
//   document.querySelectorAll('.completeOrderBtn').forEach(button => {
//     button.addEventListener('click', async (e) => {
//       const orderDiv = e.target.closest('div[data-order-id]');
//       const orderId = orderDiv.getAttribute('data-order-id');
//       try {
//         const res = await fetch(`/api/customers/${customer._id}/order/${orderId}`, {
//           method: 'PUT',
//           headers: { 'Content-Type': 'application/json' },
//           body: JSON.stringify({ status: 'Completed' })
//         });
//         if (!res.ok) throw new Error('Failed to complete order');
//         alert('Order marked complete');
//         fetchAndRenderCustomerDetails(customer._id);
//       } catch (err) {
//         alert(err.message);
//       }
//     });
//   });

//   document.querySelectorAll('.deleteOrderBtn').forEach(button => {
//     button.addEventListener('click', async (e) => {
//       const orderDiv = e.target.closest('div[data-order-id]');
//       const orderId = orderDiv.getAttribute('data-order-id');
//       if (!confirm('Delete this order?')) return;
//       try {
//         const res = await fetch(`/api/customers/${customer._id}/order/${orderId}`, {
//           method: 'DELETE'
//         });
//         if (!res.ok) throw new Error('Failed to delete order');
//         alert('Order deleted');
//         fetchAndRenderCustomerDetails(customer._id);
//       } catch (err) {
//         alert(err.message);
//       }
//     });
//   });
// }

// // On typing in search box: show suggestions
// searchInput.addEventListener('input', async () => {
//   const query = searchInput.value.trim();
//   const suggestions = await fetchCustomerSuggestions(query);
//   renderSuggestions(suggestions);
// });

// // On pressing Enter in search box: fetch full customer details if exact match
// searchInput.addEventListener('keydown', async (e) => {
//   if (e.key === 'Enter') {
//     e.preventDefault();
//     const query = searchInput.value.trim();
//     if (!query) return;

//     // Fetch all customers, find exact match by name
//     try {
//       const res = await fetch('/api/customers');
//       if (!res.ok) throw new Error('Failed to fetch customers');
//       const customers = await res.json();
//       const exactMatch = customers.find(cust => cust.name.toLowerCase() === query.toLowerCase());
//       if (exactMatch) {
//         suggestionBox.style.display = 'none';
//         fetchAndRenderCustomerDetails(exactMatch._id);
//       } else {
//         customerList.innerHTML = `<p style="color:red;">No customer found with name "${query}"</p>`;
//       }
//     } catch (err) {
//       customerList.innerHTML = `<p style="color:red;">Error fetching customers</p>`;
//     }
//   }
// });








// // 🚀 Start Server
// const PORT = process.env.PORT || 3000;
// app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
