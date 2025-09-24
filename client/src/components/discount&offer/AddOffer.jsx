import React, { useState } from "react";
import Swal from "sweetalert2";
import { useNavigate, useLocation } from "react-router-dom";
import { motion } from "framer-motion";
import { FiArrowLeft, FiLoader } from "react-icons/fi";
import { MdLocalOffer } from "react-icons/md";
import { BsPercent } from "react-icons/bs";
import ClipLoader from "react-spinners/ClipLoader";
import DOMPurify from "dompurify"; // Import DOMPurify for XSS prevention

export default function AddOffer() {
  const location = useLocation();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    promotionName: "",
    promotionCode: "",
    description: "",
    promotionType: "pDiscount",
    discountPercentage: "",
    price: location.state?.price ?? 0,
    itemName: location.state?.name ?? 0,
    itemId: location.state?.id ?? 0,
    finalPrice: "",
    startDate: "",
    endDate: "",
    applicableProducts: "apparel",
    usageLimit: "",
  });

  const [error, setError] = useState(null);

  // ---------------- Helper: Calculate Final Price ----------------
  const calculateFinalPrice = (price, discountPercentage) => {
    const p = parseFloat(price);
    const d = parseFloat(discountPercentage);
    if (!isNaN(p) && !isNaN(d)) return (p - (p * d) / 100).toFixed(2);
    return "";
  };

  // ---------------- Helper: Positive Number Validation ----------------
  const isPositiveNumber = (value) => /^\d+(\.\d{1,2})?$/.test(value);

  const handleInputChange = (e) => {
    let { name, value } = e.target;

    // ---------- FIX: Sanitize text inputs to prevent XSS ----------
    if (["promotionName", "promotionCode", "description"].includes(name)) {
      value = DOMPurify.sanitize(value);
      // DOMPurify removes any malicious HTML/JS like <script>alert('XSS')</script>
    }

    // ---------- FIX: Validate numeric fields ----------
    if (["discountPercentage", "price", "usageLimit"].includes(name)) {
      if (!isPositiveNumber(value) && value !== "") {
        Swal.fire({
          icon: "error",
          title: "Invalid Input",
          text: `${
            name === "discountPercentage"
              ? "Discount Percentage"
              : name === "price"
              ? "Price"
              : "Usage Limit"
          } must be a positive number.`,
        });
        return; // Reject invalid input
      }
    }

    const updatedFormData = { ...formData, [name]: value };

    // ---------- Recalculate final price if price/discount changes ----------
    if (name === "discountPercentage" || name === "price") {
      updatedFormData.finalPrice = calculateFinalPrice(
        updatedFormData.price,
        updatedFormData.discountPercentage
      );
    }

    setFormData(updatedFormData);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true); // Start loading

    // ---------- Required Field Validation ----------
    if (!formData.promotionName.trim()) {
      setLoading(false);
      return Swal.fire({
        icon: "error",
        title: "Validation Error",
        text: "Offer name is required.",
      });
    }

    if (!formData.promotionCode.trim()) {
      setLoading(false);
      return Swal.fire({
        icon: "error",
        title: "Validation Error",
        text: "Offer code is required.",
      });
    }

    if (!isPositiveNumber(formData.discountPercentage)) {
      setLoading(false);
      return Swal.fire({
        icon: "error",
        title: "Validation Error",
        text: "Discount percentage must be a valid positive number.",
      });
    }

    if (!isPositiveNumber(formData.usageLimit)) {
      setLoading(false);
      return Swal.fire({
        icon: "error",
        title: "Validation Error",
        text: "Usage limit must be a valid positive number.",
      });
    }

    // ---------- Date Validation ----------
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const startDate = new Date(formData.startDate);
    const endDate = new Date(formData.endDate);

    if (startDate < today) {
      setLoading(false);
      Swal.fire({
        icon: "error",
        title: "Invalid Date",
        text: "Start date cannot be in the past.",
      });
      return;
    }

    if (endDate < today) {
      setLoading(false);
      Swal.fire({
        icon: "error",
        title: "Invalid Date",
        text: "End date cannot be in the past.",
      });
      return;
    }

    if (endDate < startDate) {
      setLoading(false);
      Swal.fire({
        icon: "error",
        title: "Invalid Date",
        text: "End date cannot be before the start date.",
      });
      return;
    }

    // ---------- FIX: Sanitize entire payload before sending ----------
    const payload = {
      ...formData,
      promotionName: DOMPurify.sanitize(formData.promotionName),
      promotionCode: DOMPurify.sanitize(formData.promotionCode),
      description: DOMPurify.sanitize(formData.description),
    };

    try {
      const response = await fetch("/api/promotions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const json = await response.json();
      setLoading(false);

      if (!response.ok) {
        setError(json.error);
        Swal.fire({
          icon: "error",
          title: "Error",
          text: json.message,
        });
      } else {
        Swal.fire({
          icon: "success",
          title: "Success",
          text: "Promotion added successfully",
        });

        // ---------- Reset form ----------
        setFormData({
          promotionName: "",
          promotionCode: "",
          description: "",
          promotionType: "pDiscount",
          discountPercentage: "",
          price: "",
          finalPrice: "",
          startDate: "",
          endDate: "",
          applicableProducts: "apparel",
          usageLimit: "",
        });

        navigate("/manager/discount-management?tab=discounts");
      }
    } catch (err) {
      setLoading(false);
      Swal.fire({
        icon: "error",
        title: "Error",
        text: "Something went wrong. Please try again.",
      });
    }
  };

  return (
    <motion.div
      className="p-8 pl-20 rounded-lg shadow-md "
      style={{ backgroundColor: "#f5ebe0" }}
      initial={{ opacity: 0, y: -20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >
      <motion.div
        className="min-h-screen bg-gradient-to-r from-[#f5ebe0] to-[#e3d5ca] text-[#775c41] px-6 py-8 rounded-lg"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.5 }}
      >
        {/* Header Section */}
        <div className="flex  items-center mb-6">
          {/* Back Button */}
          <button
            className="bg-DarkColor text-white px-4 py-2 rounded-md flex items-center gap-2 hover:bg-ExtraDarkColor transition-colors"
            onClick={() => navigate(-1)}
          >
            <FiArrowLeft className="mr-2" />
          </button>
          <h2 className="text-3xl font-bold text-DarkColor ml-20">
            Add New Offer for {formData.itemName}
          </h2>
        </div>

        {/* Form Section */}
        <motion.section
          className="p-6 rounded-lg shadow-md w-11/12"
          style={{ backgroundColor: "white" }}
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.4 }}
        >
          <form onSubmit={handleSubmit}>
            <div className="grid grid-cols-2 gap-6">
              {/* Left Column */}
              <div className="flex flex-col mb-4">
                <label className="text-xl font-semibold">Offer Name</label>
                <div className="flex items-center mt-2 p-2 border rounded-lg">
                  <MdLocalOffer className="mr-2 text-xl text-DarkColor" />
                  <input
                    type="text"
                    className="w-full bg-transparent outline-none"
                    placeholder="Enter offer name"
                    name="promotionName"
                    onChange={handleInputChange}
                  />
                </div>
              </div>

              <div className="flex flex-col mb-4">
                <label className="text-xl font-semibold">Offer Code</label>
                <input
                  className="mt-2 p-2 border rounded-lg bg-transparent"
                  type="text"
                  placeholder="Offer Code"
                  name="promotionCode"
                  onChange={handleInputChange}
                />
              </div>

              <div className="flex flex-col mb-4">
                <label className="text-xl font-semibold">Description</label>
                <textarea
                  className="mt-2 p-2 border rounded-lg bg-transparent"
                  type="textarea"
                  placeholder="Description"
                  name="description"
                  onChange={handleInputChange}
                />
              </div>

              <div className="flex flex-col mb-4">
                <label className="text-xl font-semibold">Offer Type</label>
                <select
                  name="promotionType"
                  className="mt-2 p-2 border rounded-lg bg-transparent"
                  onChange={handleInputChange}
                  value={formData.promotionType}
                >
                  <option value="pDiscount">Percentage Discount</option>
                  <option value="BOGO">Buy One Get One Free</option>
                  <option value="fShipping">Free Shipping</option>
                  <option value="fGift">Free Gift</option>
                </select>
              </div>

              <div className="flex flex-col mb-4">
                <label className="text-xl font-semibold">
                  Discount Percentage
                </label>
                <div className="flex items-center mt-2 p-2 border rounded-lg">
                  <BsPercent className="mr-2 text-xl text-DarkColor" />
                  <input
                    type="text"
                    className="w-full bg-transparent outline-none"
                    placeholder="Discount Percentage"
                    name="discountPercentage"
                    onChange={handleInputChange}
                  />
                </div>
              </div>

              {/* Right Column */}
              <div className="flex flex-col mb-4">
                <label className="text-xl font-semibold">Price</label>
                <input
                  value={formData.price}
                  className="mt-2 p-2 border rounded-lg bg-transparent"
                  type="text"
                  placeholder="Price"
                  name="price"
                  onChange={handleInputChange}
                  readOnly={true}
                />
              </div>

              <div className="flex flex-col mb-4">
                <label className="text-xl font-semibold">Final Price</label>
                <input
                  className="mt-2 p-2 border rounded-lg bg-transparent"
                  type="text"
                  placeholder="Final Price"
                  name="finalPrice"
                  value={formData.finalPrice}
                  readOnly={true}
                />
              </div>

              <div className="flex flex-col mb-4">
                <label className="text-xl font-semibold">Start Date</label>
                <input
                  className="mt-2 p-2 border rounded-lg bg-transparent"
                  type="date"
                  name="startDate"
                  onChange={handleInputChange}
                />
              </div>

              <div className="flex flex-col mb-4">
                <label className="text-xl font-semibold">End Date</label>
                <input
                  className="mt-2 p-2 border rounded-lg bg-transparent"
                  type="date"
                  name="endDate"
                  onChange={handleInputChange}
                />
              </div>

              <div className="flex flex-col mb-4">
                <label className="text-xl font-semibold">
                  Applicable Products
                </label>
                <select
                  name="applicableProducts"
                  className="mt-2 p-2 border rounded-lg bg-transparent"
                  onChange={handleInputChange}
                  value={formData.applicableProducts}
                >
                  <option value="apparel">Apparel</option>
                  <option value="outerwear">Outerwear</option>
                  <option value="kidsclothing">Children's Clothing</option>
                  <option value="formalwear">Formal Wear</option>
                </select>
              </div>

              <div className="flex flex-col mb-4">
                <label className="text-xl font-semibold">Usage Limit</label>
                <input
                  className="mt-2 p-2 border rounded-lg bg-transparent"
                  type="number"
                  placeholder="Usage Limit"
                  name="usageLimit"
                  onChange={handleInputChange}
                />
              </div>
            </div>

            <button
              type="submit"
              className="bg-rose-400 p-3 rounded-lg px-8 font-bold text-xl flex items-center justify-center mt-4"
            >
              {loading ? <ClipLoader size={25} color="#fff" /> : "Add Offer"}
            </button>

            {error && <div className="error text-red-500 mt-4">{error}</div>}
          </form>
        </motion.section>
      </motion.div>
    </motion.div>
  );
}
