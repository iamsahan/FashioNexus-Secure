import Order from "../models/order.model.js";
import { v4 as uuidv4 } from "uuid";

// Helper function to sanitize order data before sending response
const sanitizeOrder = (order) => {
  const { cardInfo, ...safeOrder } = order.toObject(); // remove cardInfo
  return safeOrder;
};

export const createOrder = async (req, res) => {
  try {
    const {
      userId,
      items,
      total,
      customerInfo,
      deliveryInfo,
      paymentMethod,
      cardInfo,
    } = req.body;

    if (
      !userId ||
      !items ||
      !total ||
      !customerInfo ||
      !deliveryInfo ||
      !paymentMethod
    ) {
      return res
        .status(400)
        .json({ message: "All required fields must be provided." });
    }

    // Generate a unique order ID
    const orderId = `ORD-${uuidv4().slice(0, 6).toUpperCase()}`;

    // Only store safe card info
    const safeCardInfo =
      paymentMethod === "Card"
        ? {
            last4: cardInfo?.cardNumber?.slice(-4), // Only last 4 digits
            expiryDate: cardInfo?.expiryDate, // Optional
          }
        : undefined;

    const newOrder = new Order({
      userId,
      items,
      total,
      customerInfo,
      deliveryInfo,
      paymentMethod,
      cardInfo: safeCardInfo, // No raw card number or CVV
      orderId,
    });

    const savedOrder = await newOrder.save();
    res.status(201).json({
      message: "Order created successfully",
      orderId: savedOrder.orderId,
    });
  } catch (error) {
    console.error("Error creating order:", error);
    res.status(500).json({ message: "Server error" });
  }
};

// Fetch orders by userId
export const OrderByUser = async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.params.userId }).select(
      "-cardInfo" // exclude entire cardInfo object
    );
    res.json(orders);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export const AllOrder = async (req, res) => {
  try {
    const orders = await Order.find().select("-cardInfo");
    res.json(orders);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export const deleteOrder = async (req, res) => {
  try {
    await Order.findByIdAndDelete(req.params.orderId);
    res.json({ message: "Order deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export const updateStatus = async (req, res) => {
  try {
    const { status } = req.body;
    const response = await Order.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    ).select("-cardInfo");
    res.json(response);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export const updateOrder = async (req, res) => {
  try {
    const order = await Order.findByIdAndUpdate(req.params.orderId, req.body, {
      new: true,
    }).select("-cardInfo");
    res.json(order);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
