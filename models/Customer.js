// models/Customer.js
const mongoose = require('mongoose');

const orderSchema = new mongoose.Schema({
    returnDate: { type: Date, required: true },
    note:       { type: String, required: true },
    status:     { type: String, default: 'Pending' },
    createdAt:  { type: Date, default: Date.now } // 👈 Added createdAt field
});

const customerSchema = new mongoose.Schema({
    name:         { type: String, required: true },
    phone:        { type: String, required: true },
    gender:       { type: String, required: true },
    shoulder:     { type: Number, required: true },
    chest:        { type: Number, required: true },
    hip:          { type: Number, required: true },
    sleeveLength: { type: Number, required: true },
    user:         { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    orders: [orderSchema]
});

module.exports = mongoose.model('Customer', customerSchema);

