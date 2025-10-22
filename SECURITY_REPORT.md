# 🔒 FashioNexus Security Vulnerability Report

**Generated:** 10/22/2025, 8:41:19 PM  
**Total Issues:** 44  
**Files Scanned:** 23

## 📊 Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 25 |
| 🟠 HIGH | 18 |
| 🟡 MEDIUM | 1 |
| **TOTAL** | **44** |

---

## 🔴 Injection Risks (NoSQL Injection)

**Severity:** CRITICAL  
**Issues Found:** 11

### Issue 1

- **File:** `/api/controllers/auth.controllers.js`
- **Line:** 58
- **Description:** Direct use of user input in database query - NoSQL injection risk
- **Code:**
```javascript
const user = await User.findOne({ email: req.body.email });
```

### Issue 2

- **File:** `/api/controllers/auth.controllers.js`
- **Line:** 58
- **Description:** Direct email from request body without validation
- **Code:**
```javascript
const user = await User.findOne({ email: req.body.email });
```

### Issue 3

- **File:** `/api/controllers/auth.controllers.js`
- **Line:** 75
- **Description:** Direct email from request body without validation
- **Code:**
```javascript
email: req.body.email,
```

### Issue 4

- **File:** `/api/controllers/inventory.controller.js`
- **Line:** 82
- **Description:** Unvalidated parseInt on user input - potential injection
- **Code:**
```javascript
const limit = parseInt(req.query.limit) || 10;
```

### Issue 5

- **File:** `/api/controllers/inventory.controller.js`
- **Line:** 83
- **Description:** Unvalidated parseInt on user input - potential injection
- **Code:**
```javascript
const startIndex = parseInt(req.query.startIndex) || 0;
```

### Issue 6

- **File:** `/api/controllers/order.controller.js`
- **Line:** 57
- **Description:** Direct use of user input in database query - NoSQL injection risk
- **Code:**
```javascript
const orders = await Order.find({ userId: req.params.userId });
```

### Issue 7

- **File:** `/api/controllers/promotion.controllers.js`
- **Line:** 133
- **Description:** Unvalidated parseInt on user input - potential injection
- **Code:**
```javascript
const limit = parseInt(req.query.limit) || 10;
```

### Issue 8

- **File:** `/api/controllers/promotion.controllers.js`
- **Line:** 134
- **Description:** Unvalidated parseInt on user input - potential injection
- **Code:**
```javascript
const startIndex = parseInt(req.query.startIndex) || 0;
```

### Issue 9

- **File:** `/api/controllers/user.controllers.js`
- **Line:** 71
- **Description:** Unvalidated parseInt on user input - potential injection
- **Code:**
```javascript
const limit = parseInt(req.query.limit) || 50;
```

### Issue 10

- **File:** `/api/controllers/user.controllers.js`
- **Line:** 72
- **Description:** Unvalidated parseInt on user input - potential injection
- **Code:**
```javascript
const startIndex = parseInt(req.query.startIndex) || 0;
```

### Issue 11

- **File:** `/api/controllers/user.controllers.js`
- **Line:** 28
- **Description:** Direct email from request body without validation
- **Code:**
```javascript
email: req.body.email,
```


---

## 🔴 Insecure File Upload

**Severity:** CRITICAL  
**Issues Found:** 2

### Issue 1

- **File:** `/api/index.js`
- **Line:** 63
- **Description:** Filename generation using only timestamp - predictable
- **Code:**
```javascript
cb(null, Date.now() + path.extname(file.originalname)); // Unique file name
```

### Issue 2

- **File:** `/api/index.js`
- **Line:** 1
- **Description:** Using original filename - potential path traversal risk


---

## 🟠 Insecure OTP Implementation

**Severity:** HIGH  
**Issues Found:** 6

### Issue 1

- **File:** `/api/controllers/otp.controller.js`
- **Line:** 13
- **Description:** OTP stored in-memory Map - not persistent or secure for production
- **Code:**
```javascript
const otpMap = new Map(); // Key: email, Value: OTP
```

### Issue 2

- **File:** `/api/controllers/otp.controller.js`
- **Line:** 31
- **Description:** OTP stored without expiration time
- **Code:**
```javascript
otpMap.set(email, otp); // Store OTP for the email
```

### Issue 3

- **File:** `/api/index.js`
- **Line:** 122
- **Description:** OTP stored in-memory Map - not persistent or secure for production
- **Code:**
```javascript
const otpMap = new Map(); // Key: email, Value: OTP
```

### Issue 4

- **File:** `/api/index.js`
- **Line:** 135
- **Description:** OTP endpoint without rate limiting - vulnerable to brute force
- **Code:**
```javascript
app.post("/api/auth/sendotp", (req, res) => {
```

### Issue 5

- **File:** `/api/index.js`
- **Line:** 216
- **Description:** OTP endpoint without rate limiting - vulnerable to brute force
- **Code:**
```javascript
app.post("/api/auth/verifyotp", (req, res) => {
```

### Issue 6

- **File:** `/api/index.js`
- **Line:** 140
- **Description:** OTP stored without expiration time
- **Code:**
```javascript
otpMap.set(email, otp); // Store OTP for the email
```


---

## 🔴 Missing Authentication on Critical Routes

**Severity:** CRITICAL  
**Issues Found:** 12

### Issue 1

- **File:** `/api/routes/discount.route.js`
- **Line:** 11
- **Description:** Critical route without authentication middleware
- **Code:**
```javascript
router.post("/add", createDiscount);
```

### Issue 2

- **File:** `/api/routes/discount.route.js`
- **Line:** 13
- **Description:** Critical route without authentication middleware
- **Code:**
```javascript
router.put("/update/:id", updateDiscounts);
```

### Issue 3

- **File:** `/api/routes/discount.route.js`
- **Line:** 14
- **Description:** Critical route without authentication middleware
- **Code:**
```javascript
router.delete("/delete/:id", deleteDiscounts);
```

### Issue 4

- **File:** `/api/routes/inventory.routs.js`
- **Line:** 22
- **Description:** Critical route without authentication middleware
- **Code:**
```javascript
router.post("/add", createInventory);
```

### Issue 5

- **File:** `/api/routes/order.rout.js`
- **Line:** 13
- **Description:** Critical route without authentication middleware
- **Code:**
```javascript
router.post("/add", createOrder);
```

### Issue 6

- **File:** `/api/routes/order.rout.js`
- **Line:** 16
- **Description:** Critical route without authentication middleware
- **Code:**
```javascript
router.put("/update/:orderId", updateOrder);
```

### Issue 7

- **File:** `/api/routes/order.rout.js`
- **Line:** 17
- **Description:** Critical route without authentication middleware
- **Code:**
```javascript
router.put("/status/:id", updateStatus);
```

### Issue 8

- **File:** `/api/routes/order.rout.js`
- **Line:** 18
- **Description:** Critical route without authentication middleware
- **Code:**
```javascript
router.delete("/delete/:orderId", deleteOrder);
```

### Issue 9

- **File:** `/api/routes/user.route.js`
- **Line:** 17
- **Description:** Critical route without authentication middleware
- **Code:**
```javascript
router.delete("/delete-user/:id", deleteUserByid);
```

### Issue 10

- **File:** `/api/routes/user.route.js`
- **Line:** 19
- **Description:** Critical route without authentication middleware
- **Code:**
```javascript
router.post("/add", addUser);
```

### Issue 11

- **File:** `/api/routes/user.route.js`
- **Line:** 21
- **Description:** Critical route without authentication middleware
- **Code:**
```javascript
router.post("/update/:id", veryfyTocken, updateUser);
```

### Issue 12

- **File:** `/api/routes/user.route.js`
- **Line:** 22
- **Description:** Critical route without authentication middleware
- **Code:**
```javascript
router.delete("/delete/:id", veryfyTocken, deleteUser);
```


---

## 🟠 Missing CSRF Protection

**Severity:** HIGH  
**Issues Found:** 4

### Issue 1

- **File:** `/api/controllers/auth.controllers.js`
- **Line:** 1
- **Description:** Cookie-based authentication without CSRF protection

### Issue 2

- **File:** `/api/controllers/auth.controllers.js`
- **Line:** 47
- **Description:** Cookie set without sameSite or secure flags - CSRF risk
- **Code:**
```javascript
.cookie("access_token", token, { httpOnly: true })
```

### Issue 3

- **File:** `/api/controllers/auth.controllers.js`
- **Line:** 63
- **Description:** Cookie set without sameSite or secure flags - CSRF risk
- **Code:**
```javascript
.cookie("access_token", token, { httpOnly: true })
```

### Issue 4

- **File:** `/api/controllers/auth.controllers.js`
- **Line:** 84
- **Description:** Cookie set without sameSite or secure flags - CSRF risk
- **Code:**
```javascript
.cookie("access_token", token, { httpOnly: true })
```


---

## 🟡 Missing Security Headers

**Severity:** MEDIUM  
**Issues Found:** 1

### Issue 1

- **File:** `/api/index.js`
- **Line:** 1
- **Description:** Application not using helmet middleware for security headers


---

## 🟠 Sensitive Data Exposure

**Severity:** HIGH  
**Issues Found:** 8

### Issue 1

- **File:** `/api/controllers/auth.controllers.js`
- **Line:** 40
- **Description:** Sensitive data being logged to console
- **Code:**
```javascript
console.log("Password mismatch."); // Debugging
```

### Issue 2

- **File:** `/api/controllers/otp.controller.js`
- **Line:** 7
- **Description:** Hardcoded credentials in source code
- **Code:**
```javascript
user: "sadeepmalaka2@gmail.com",
```

### Issue 3

- **File:** `/api/controllers/otp.controller.js`
- **Line:** 8
- **Description:** Hardcoded credentials in source code
- **Code:**
```javascript
pass: "bfxr wzmt jalb grxp", // Consider using environment variables for sensitive information
```

### Issue 4

- **File:** `/api/controllers/otp.controller.js`
- **Line:** 34
- **Description:** Hardcoded credentials in source code
- **Code:**
```javascript
from: "sadeepmalaka2@gmail.com",
```

### Issue 5

- **File:** `/api/index.js`
- **Line:** 26
- **Description:** Hardcoded credentials in source code
- **Code:**
```javascript
"mongodb+srv://pgmsadeep:1234@cluster0.phudmlq.mongodb.net/fashion?retryWrites=true&w=majority";
```

### Issue 6

- **File:** `/api/index.js`
- **Line:** 116
- **Description:** Hardcoded credentials in source code
- **Code:**
```javascript
user: "sadeepmalaka2@gmail.com",
```

### Issue 7

- **File:** `/api/index.js`
- **Line:** 117
- **Description:** Hardcoded credentials in source code
- **Code:**
```javascript
pass: "bfxr wzmt jalb grxp",
```

### Issue 8

- **File:** `/api/index.js`
- **Line:** 143
- **Description:** Hardcoded credentials in source code
- **Code:**
```javascript
from: "sadeepmalaka2@gmail.com",
```


---

## 🔧 Recommendations

### Critical Priority
1. Implement authentication middleware on all critical routes
2. Fix NoSQL injection vulnerabilities by validating user input
3. Add file upload validation and security measures

### High Priority
4. Remove hardcoded credentials and use environment variables
5. Implement secure OTP generation and storage
6. Add CSRF protection for cookie-based authentication
7. Sanitize all user input to prevent XSS

### Medium Priority
8. Add security headers using helmet middleware
9. Configure CORS properly instead of using wildcards
10. Implement rate limiting on all endpoints

