import Inventory from "../models/inventory.model.js";
import mongoose from "mongoose";
import Joi from "joi"; // for validation
import { safeParseInt, sanitizeSearchQuery } from "../utils/security.js";

// ------------------- Validation Schemas using Joi -------------------
// This schema defines the structure and validation rules for inventory items
const inventorySchema = Joi.object({
  ItemName: Joi.string().min(2).max(100).required(), //must be string between 2 and 100 characters
  Category: Joi.string()
    .valid(
      "Men's Clothing",
      "Women's Clothing",
      "Kids' Clothing",
      "Accessories",
      "Footwear"
    )
    .required(),
  price: Joi.number().min(0).required(),
  quantity: Joi.number().min(0).required(),
  haveOffer: Joi.boolean().optional(),
  SupplierName: Joi.string().required(),
  SupplierContact: Joi.string().required(),
  StockStatus: Joi.string().required(),
  ReorderLevel: Joi.number().required(),
  StockQuantity: Joi.number().required(),
  description: Joi.string().required(),
  UnitPrice: Joi.number().required(),
  SKU: Joi.number().required(),
});

//GET all inventories
export const getInventories = async (req, res) => {
  const inventories = await Inventory.find({}).sort({ createdAt: -1 });

  res.status(200).json(inventories);
};

//GET a single inventory
export const getInventory = async (req, res) => {
  const { id } = req.params;

  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(404).json({ error: "No such inventory" });
  }

  const inventory = await Inventory.findById(id);

  if (!inventory) {
    return res.status(404).json({ error: "No such inventory" });
  }

  res.status(200).json(inventory);
};

//create new inventory
export const createInventory = async (req, res, next) => {
  try {
    // validate body (validate incoming request data using joi schema)
    const { error, value } = inventorySchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });

    const addinventory = await Inventory.create(value); // safe input
    return res.status(201).json(addinventory);
  } catch (error) {
    next(error);
  }
};

//DELETE an inventory
export const deleteInventory = async (req, res) => {
  const { id } = req.params;

  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(404).json({ error: "No such inventory" });
  }

  const inventory = await Inventory.findOneAndDelete({ _id: id });

  if (!inventory) {
    return res.status(400).json({ error: "No such inventory" });
  }

  res.status(200).json(inventory);
};

//UPDATE an inventory
export const updateInventory = async (req, res) => {
  const { id } = req.params;

  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(404).json({ error: "No such inventory" });
  }

  // validate the data to be updated using Joi data
  const { error, value } = inventorySchema.validate(req.body, {
    allowUnknown: false,
  });
  if (error) return res.status(400).json({ error: error.details[0].message });

  const inventory = await Inventory.findOneAndUpdate(
    { _id: id },
    { $set: value }, // no spreading req.body
    { new: true }
  );

  if (!inventory) {
    return res.status(400).json({ error: "No such inventory" });
  }

  res.status(200).json(inventory);
};

//search

export const getInventorySearch = async (req, res, next) => {
  try {
    // Safe input validation with hard caps
    const limit = safeParseInt(req.query.limit, 10, 1, 50);
    const startIndex = safeParseInt(req.query.startIndex, 0, 0, 10000);

    // validate category
    let Category = req.query.category;
    if (!Category || Category === "all") {
      Category = {
        $in: [
          "Men's Clothing",
          "Women's Clothing",
          "Kids' Clothing",
          "Accessories",
          "Footwear",
        ],
      };
    }

    // sanitize searchTerm (no regex DoS)
    const searchTerm = req.query.searchTerm || "";
    const safeSearch = searchTerm.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); // escape regex chars

    // allow only safe sort fields
    const allowedSortFields = ["createdAt", "price", "ItemName"];
    const sortField = allowedSortFields.includes(req.query.sort)
      ? req.query.sort
      : "createdAt";

    const order = req.query.order === "asc" ? 1 : -1;

    const events = await Inventory.find({
      ItemName: { $regex: safeSearch, $options: "i" },
      Category,
    })
      .sort({ [sortField]: order })
      .skip(startIndex)
      .limit(limit);

    return res.status(200).json(events);
  } catch (error) {
    console.log("err", error);
    next(error);
  }
};

export const getInventorieswithOffers = async (req, res) => {
  try {
    // Find inventories where haveOffer is true and sort by createdAt in descending order
    const inventories = await Inventory.find({ haveOffer: true }).sort({
      createdAt: -1,
    });

    // Check if any inventories were found
    if (!inventories.length) {
      return res
        .status(404)
        .json({ message: "No inventories found with offers." });
    }

    res.status(200).json(inventories);
  } catch (error) {
    console.error("Error fetching inventories:", error);
    res
      .status(500)
      .json({ error: "An error occurred while fetching inventories." });
  }
};
