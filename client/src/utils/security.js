/**
 * Client-side Security Utilities
 * Handles security-related functions for the FashioNexus frontend
 */

/**
 * Sanitize HTML content to prevent XSS attacks
 * @param {string} html - HTML content to sanitize
 * @returns {string} Sanitized HTML
 */
export const sanitizeHTML = (html) => {
  if (!html) return "";

  // Create a temporary div to parse HTML
  const temp = document.createElement("div");
  temp.textContent = html;
  return temp.innerHTML;
};

/**
 * Validate and sanitize user input
 * @param {string} input - User input to validate
 * @param {Object} options - Validation options
 * @returns {string} Sanitized input
 */
export const sanitizeInput = (input, options = {}) => {
  if (!input || typeof input !== "string") return "";

  let sanitized = input.trim();

  // Remove potentially dangerous characters
  if (options.removeHTML) {
    sanitized = sanitized.replace(/<[^>]*>/g, "");
  }

  // Remove script tags and event handlers
  sanitized = sanitized.replace(
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    ""
  );
  sanitized = sanitized.replace(/on\w+="[^"]*"/gi, "");
  sanitized = sanitized.replace(/javascript:/gi, "");

  // Limit length if specified
  if (options.maxLength) {
    sanitized = sanitized.substring(0, options.maxLength);
  }

  return sanitized;
};

/**
 * Validate email format
 * @param {string} email - Email to validate
 * @returns {boolean} True if valid email format
 */
export const isValidEmail = (email) => {
  if (!email || typeof email !== "string") return false;

  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return emailRegex.test(email) && email.length <= 254;
};

/**
 * Validate password strength
 * @param {string} password - Password to validate
 * @returns {Object} Validation result with strength score and issues
 */
export const validatePassword = (password) => {
  if (!password || typeof password !== "string") {
    return { isValid: false, strength: 0, issues: ["Password is required"] };
  }

  const issues = [];
  let strength = 0;

  // Length check
  if (password.length < 8) {
    issues.push("Password must be at least 8 characters long");
  } else {
    strength += 1;
  }

  // Uppercase check
  if (!/[A-Z]/.test(password)) {
    issues.push("Password must contain at least one uppercase letter");
  } else {
    strength += 1;
  }

  // Lowercase check
  if (!/[a-z]/.test(password)) {
    issues.push("Password must contain at least one lowercase letter");
  } else {
    strength += 1;
  }

  // Number check
  if (!/\d/.test(password)) {
    issues.push("Password must contain at least one number");
  } else {
    strength += 1;
  }

  // Special character check
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    issues.push("Password must contain at least one special character");
  } else {
    strength += 1;
  }

  return {
    isValid: issues.length === 0,
    strength: Math.min(strength, 5),
    issues,
  };
};

/**
 * Generate CSRF token for requests
 * @returns {string} CSRF token
 */
export const generateCSRFToken = () => {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
};

/**
 * Secure local storage wrapper
 */
export const secureStorage = {
  set: (key, value) => {
    try {
      if (!key || typeof key !== "string") return false;

      // Sanitize key
      const sanitizedKey = sanitizeInput(key, {
        removeHTML: true,
        maxLength: 100,
      });

      // Store with timestamp for expiration
      const data = {
        value,
        timestamp: Date.now(),
      };

      localStorage.setItem(sanitizedKey, JSON.stringify(data));
      return true;
    } catch (error) {
      console.error("Secure storage set error:", error);
      return false;
    }
  },

  get: (key, maxAge = 24 * 60 * 60 * 1000) => {
    // Default 24 hours
    try {
      if (!key || typeof key !== "string") return null;

      const sanitizedKey = sanitizeInput(key, {
        removeHTML: true,
        maxLength: 100,
      });
      const stored = localStorage.getItem(sanitizedKey);

      if (!stored) return null;

      const data = JSON.parse(stored);

      // Check if expired
      if (Date.now() - data.timestamp > maxAge) {
        localStorage.removeItem(sanitizedKey);
        return null;
      }

      return data.value;
    } catch (error) {
      console.error("Secure storage get error:", error);
      return null;
    }
  },

  remove: (key) => {
    try {
      if (!key || typeof key !== "string") return false;

      const sanitizedKey = sanitizeInput(key, {
        removeHTML: true,
        maxLength: 100,
      });
      localStorage.removeItem(sanitizedKey);
      return true;
    } catch (error) {
      console.error("Secure storage remove error:", error);
      return false;
    }
  },

  clear: () => {
    try {
      localStorage.clear();
      return true;
    } catch (error) {
      console.error("Secure storage clear error:", error);
      return false;
    }
  },
};

/**
 * Rate limiting helper for client-side
 */
export class RateLimiter {
  constructor(maxRequests = 10, windowMs = 60000) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
    this.requests = new Map();
  }

  isAllowed(identifier) {
    const now = Date.now();
    const key = sanitizeInput(identifier, { removeHTML: true, maxLength: 100 });

    if (!this.requests.has(key)) {
      this.requests.set(key, []);
    }

    const requestTimes = this.requests.get(key);

    // Remove old requests outside the window
    const validRequests = requestTimes.filter(
      (time) => now - time < this.windowMs
    );

    if (validRequests.length >= this.maxRequests) {
      return false;
    }

    validRequests.push(now);
    this.requests.set(key, validRequests);

    return true;
  }
}

export default {
  sanitizeHTML,
  sanitizeInput,
  isValidEmail,
  validatePassword,
  generateCSRFToken,
  secureStorage,
  RateLimiter,
};
