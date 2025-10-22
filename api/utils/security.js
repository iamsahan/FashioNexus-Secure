// Security utilities for input validation and sanitization

/**
 * Safely parse integer with validation
 * @param {string} value - Input value to parse
 * @param {number} defaultValue - Default value if parsing fails
 * @param {number} min - Minimum allowed value
 * @param {number} max - Maximum allowed value
 * @returns {number} Safely parsed integer
 */
export const safeParseInt = (
  value,
  defaultValue = 0,
  min = 0,
  max = Number.MAX_SAFE_INTEGER
) => {
  if (!value || typeof value !== "string") return defaultValue;

  const parsed = parseInt(value, 10);
  if (isNaN(parsed)) return defaultValue;

  return Math.min(Math.max(parsed, min), max);
};

/**
 * Validate and sanitize email input
 * @param {string} email - Email to validate
 * @returns {string|null} Sanitized email or null if invalid
 */
export const validateEmail = (email) => {
  if (!email || typeof email !== "string") return null;

  const sanitized = email.toLowerCase().trim();
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  return emailRegex.test(sanitized) ? sanitized : null;
};

/**
 * Validate MongoDB ObjectId
 * @param {string} id - ID to validate
 * @returns {boolean} True if valid ObjectId format
 */
export const isValidObjectId = (id) => {
  if (!id || typeof id !== "string") return false;
  return /^[0-9a-fA-F]{24}$/.test(id);
};

/**
 * Sanitize search query to prevent NoSQL injection
 * @param {string} query - Search query
 * @returns {string} Sanitized query
 */
export const sanitizeSearchQuery = (query) => {
  if (!query || typeof query !== "string") return "";

  // Remove special MongoDB operators and characters
  return query
    .replace(/[${}]/g, "") // Remove MongoDB operators
    .trim()
    .substring(0, 100); // Limit length
};

/**
 * Validate file extension
 * @param {string} filename - Filename to validate
 * @param {string[]} allowedExtensions - Allowed file extensions
 * @returns {boolean} True if extension is allowed
 */
export const isValidFileExtension = (
  filename,
  allowedExtensions = [".jpg", ".jpeg", ".png", ".gif"]
) => {
  if (!filename || typeof filename !== "string") return false;

  const ext = filename.toLowerCase().substring(filename.lastIndexOf("."));
  return allowedExtensions.includes(ext);
};

/**
 * Sanitize filename to prevent path traversal
 * @param {string} filename - Filename to sanitize
 * @returns {string} Sanitized filename
 */
export const sanitizeFilename = (filename) => {
  if (!filename || typeof filename !== "string") return "unknown";

  return filename
    .replace(/[^a-zA-Z0-9.-]/g, "_") // Replace special chars
    .replace(/\.{2,}/g, ".") // Remove multiple dots
    .substring(0, 100); // Limit length
};
