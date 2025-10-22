/**
 * Secure HTTP Client for FashioNexus
 * Handles API requests with security considerations
 */

import { sanitizeInput, generateCSRFToken, secureStorage } from "./security.js";

class SecureHttpClient {
  constructor(baseURL = "/api") {
    this.baseURL = baseURL;
    this.defaultHeaders = {
      "Content-Type": "application/json",
      "X-Requested-With": "XMLHttpRequest",
    };
  }

  /**
   * Add CSRF token to headers
   */
  async addCSRFToken(headers = {}) {
    try {
      // Try to get CSRF token from server
      const response = await fetch(`${this.baseURL}/csrf-token`, {
        credentials: "include",
      });

      if (response.ok) {
        const data = await response.json();
        headers["X-CSRF-Token"] = data.csrfToken;
      }
    } catch (error) {
      console.warn("Could not fetch CSRF token:", error.message);
      // Fallback to client-generated token
      headers["X-CSRF-Token"] = generateCSRFToken();
    }

    return headers;
  }

  /**
   * Secure fetch wrapper
   */
  async secureRequest(url, options = {}) {
    try {
      // Sanitize URL
      const sanitizedUrl = sanitizeInput(url, { maxLength: 2000 });
      const fullUrl = sanitizedUrl.startsWith("http")
        ? sanitizedUrl
        : `${this.baseURL}${sanitizedUrl}`;

      // Prepare headers
      let headers = { ...this.defaultHeaders, ...options.headers };

      // Add CSRF token for state-changing requests
      if (
        ["POST", "PUT", "DELETE", "PATCH"].includes(
          options.method?.toUpperCase()
        )
      ) {
        headers = await this.addCSRFToken(headers);
      }

      // Add auth token if available
      const authToken = secureStorage.get("authToken");
      if (authToken) {
        headers["Authorization"] = `Bearer ${authToken}`;
      }

      const requestOptions = {
        ...options,
        headers,
        credentials: "include", // Include cookies for auth
        mode: "cors",
      };

      // Sanitize request body if it's a string
      if (requestOptions.body && typeof requestOptions.body === "string") {
        try {
          const parsed = JSON.parse(requestOptions.body);
          // Re-stringify to ensure clean JSON
          requestOptions.body = JSON.stringify(parsed);
        } catch {
          // If not JSON, sanitize as string
          requestOptions.body = sanitizeInput(requestOptions.body, {
            maxLength: 10000,
          });
        }
      }

      const response = await fetch(fullUrl, requestOptions);

      // Handle common security responses
      if (response.status === 403) {
        throw new Error("Access denied. Please check your permissions.");
      }

      if (response.status === 429) {
        throw new Error("Too many requests. Please try again later.");
      }

      return response;
    } catch (error) {
      console.error("Secure request error:", error);
      throw error;
    }
  }

  /**
   * GET request
   */
  async get(url, options = {}) {
    return this.secureRequest(url, { ...options, method: "GET" });
  }

  /**
   * POST request
   */
  async post(url, data, options = {}) {
    return this.secureRequest(url, {
      ...options,
      method: "POST",
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  /**
   * PUT request
   */
  async put(url, data, options = {}) {
    return this.secureRequest(url, {
      ...options,
      method: "PUT",
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  /**
   * DELETE request
   */
  async delete(url, options = {}) {
    return this.secureRequest(url, { ...options, method: "DELETE" });
  }

  /**
   * PATCH request
   */
  async patch(url, data, options = {}) {
    return this.secureRequest(url, {
      ...options,
      method: "PATCH",
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  /**
   * Secure file upload
   */
  async uploadFile(url, file, additionalData = {}, options = {}) {
    try {
      if (!file || !(file instanceof File)) {
        throw new Error("Invalid file provided");
      }

      // Validate file type and size
      const allowedTypes = [
        "image/jpeg",
        "image/png",
        "image/webp",
        "image/jpg",
      ];
      const maxSize = 5 * 1024 * 1024; // 5MB

      if (!allowedTypes.includes(file.type)) {
        throw new Error(
          "Invalid file type. Only JPG, PNG, and WEBP files are allowed."
        );
      }

      if (file.size > maxSize) {
        throw new Error("File size too large. Maximum size is 5MB.");
      }

      const formData = new FormData();
      formData.append("file", file);

      // Add additional data
      Object.keys(additionalData).forEach((key) => {
        const sanitizedKey = sanitizeInput(key, {
          removeHTML: true,
          maxLength: 100,
        });
        const sanitizedValue = sanitizeInput(String(additionalData[key]), {
          maxLength: 1000,
        });
        formData.append(sanitizedKey, sanitizedValue);
      });

      // Prepare headers without Content-Type (let browser set it for FormData)
      let headers = { ...options.headers };
      delete headers["Content-Type"];

      // Add CSRF token
      headers = await this.addCSRFToken(headers);

      return this.secureRequest(url, {
        ...options,
        method: "POST",
        body: formData,
        headers,
      });
    } catch (error) {
      console.error("File upload error:", error);
      throw error;
    }
  }
}

// Create and export a singleton instance
const httpClient = new SecureHttpClient();

export default httpClient;
export { SecureHttpClient };
