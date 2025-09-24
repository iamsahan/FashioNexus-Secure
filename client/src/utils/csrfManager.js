// CSRF Token utility for client-side requests
class CSRFTokenManager {
  constructor() {
    this.token = null;
    this.tokenPromise = null;
  }

  // Get CSRF token from server
  async getCSRFToken() {
    if (this.tokenPromise) {
      return this.tokenPromise;
    }

    this.tokenPromise = fetch("/api/csrf-token", {
      method: "GET",
      credentials: "include", // Include cookies
      headers: {
        "Content-Type": "application/json",
      },
    })
      .then((response) => {
        if (!response.ok) {
          throw new Error("Failed to get CSRF token");
        }
        return response.json();
      })
      .then((data) => {
        this.token = data.csrfToken;
        this.tokenPromise = null; // Reset promise
        return this.token;
      })
      .catch((error) => {
        this.tokenPromise = null; // Reset promise on error
        throw error;
      });

    return this.tokenPromise;
  }

  // Get token from cookie (fallback method)
  getTokenFromCookie() {
    const cookies = document.cookie.split(";");
    for (let cookie of cookies) {
      const [name, value] = cookie.trim().split("=");
      if (name === "csrf_token") {
        return decodeURIComponent(value);
      }
    }
    return null;
  }

  // Make authenticated request with CSRF token
  async makeSecureRequest(url, options = {}) {
    // Skip CSRF for GET requests
    if (options.method === "GET" || !options.method) {
      return fetch(url, {
        ...options,
        credentials: "include",
      });
    }

    // Get CSRF token
    const token = await this.getCSRFToken();

    // Add CSRF token to headers
    const headers = {
      "Content-Type": "application/json",
      "X-CSRF-Token": token,
      ...options.headers,
    };

    return fetch(url, {
      ...options,
      credentials: "include",
      headers,
    });
  }

  // Helper method for POST requests
  async post(url, data, options = {}) {
    return this.makeSecureRequest(url, {
      method: "POST",
      body: JSON.stringify(data),
      ...options,
    });
  }

  // Helper method for PUT requests
  async put(url, data, options = {}) {
    return this.makeSecureRequest(url, {
      method: "PUT",
      body: JSON.stringify(data),
      ...options,
    });
  }

  // Helper method for DELETE requests
  async delete(url, options = {}) {
    return this.makeSecureRequest(url, {
      method: "DELETE",
      ...options,
    });
  }

  // Clear stored token (call on logout)
  clearToken() {
    this.token = null;
    this.tokenPromise = null;
  }
}

// Create singleton instance
const csrfManager = new CSRFTokenManager();

export default csrfManager;
