# Authentication and Role-Based Access Control

This project now implements proper authentication and role-based access control using custom middleware.

## Middleware Functions

### `authenticate`

- Validates JWT tokens from cookies
- Fetches user information from database
- Sets `req.user` with user details

### `requireManager`

- Ensures the authenticated user is a manager (`ismanager: true`)
- Returns 403 error if user is not a manager

### `requireCustomer`

- Ensures the authenticated user is a customer
- Returns 403 error if user is not a customer

### `requireSelfOrManager`

- Allows users to access their own resources
- Allows managers to access any resource
- Useful for user profile operations

## Route Protection Implementation

### Public Routes (No Authentication Required)

- `GET /api/discount/get` - View discounts
- `GET /api/inventories/all-offers` - View inventory with offers
- `GET /api/inventories/search/get` - Search inventory
- `GET /api/inventories/:id` - View specific inventory item
- `GET /api/promotions/` - View promotions
- `GET /api/promotions/search/get` - Search promotions
- `GET /api/promotions/offers/:itemId` - View offers by item
- `GET /api/promotions/:id` - View specific promotion
- `GET /api/user/test` - Test endpoint

### Customer Routes (Authentication Required)

- `POST /api/order/add` - Create new order

### Manager-Only Routes (Manager Authentication Required)

- `GET /api/order/get` - View all orders
- `PUT /api/order/update/:orderId` - Update order
- `PUT /api/order/status/:id` - Update order status
- `DELETE /api/order/delete/:orderId` - Delete order
- `GET /api/user/all-Users` - View all users
- `DELETE /api/user/delete-user/:id` - Delete user by ID
- `GET /api/user/search` - Search users
- `POST /api/user/add` - Add new user
- `POST /api/discount/add` - Create discount
- `PUT /api/discount/update/:id` - Update discount
- `DELETE /api/discount/delete/:id` - Delete discount
- `POST /api/inventories/add` - Add inventory item
- `DELETE /api/inventories/:id` - Delete inventory item
- `PATCH /api/inventories/:id` - Update inventory item
- `POST /api/promotions/` - Create promotion
- `DELETE /api/promotions/:id` - Delete promotion
- `PATCH /api/promotions/:id` - Update promotion

### Self or Manager Access Routes

- `GET /api/order/get/:userId` - View orders by user (own orders or manager access)
- `POST /api/user/update/:id` - Update user (own profile or manager access)
- `DELETE /api/user/delete/:id` - Delete user (own account or manager access)
- `GET /api/user/:id` - Get user details (own profile or manager access)

## User Context

After authentication, `req.user` contains:

```javascript
{
  id: "user_mongodb_id",
  username: "username",
  email: "user@example.com",
  usertype: "customer" | "staff" | etc,
  ismanager: true | false
}
```

## Error Responses

### 401 Unauthorized

- No token provided
- Invalid token
- Token expired
- User not found

### 403 Forbidden

- Insufficient permissions
- Manager access required
- Customer access required
- Access denied for resource

## Usage Examples

### Protecting a route with authentication only:

```javascript
import { authenticate } from "../middleware/auth.middleware.js";

router.get("/protected", authenticate, controller);
```

### Protecting a route for managers only:

```javascript
import { authenticate, requireManager } from "../middleware/auth.middleware.js";

router.post("/admin-action", authenticate, requireManager, controller);
```

### Protecting a route for self or manager access:

```javascript
import {
  authenticate,
  requireSelfOrManager,
} from "../middleware/auth.middleware.js";

router.get("/user/:id", authenticate, requireSelfOrManager, controller);
```

## Security Benefits

1. **Separation of Concerns**: Clear separation between regular users and managers
2. **Resource Protection**: Sensitive operations are protected by role-based access
3. **Self-Service**: Users can manage their own resources
4. **Admin Control**: Managers have full administrative access
5. **Database Validation**: User existence is verified on each request
6. **Token Security**: JWT tokens are properly validated

## Testing Access Control

### Customer User Testing:

- Can create orders
- Can view/update their own profile
- Cannot access admin functions
- Cannot view other users' data

### Manager User Testing:

- Can access all admin functions
- Can manage all resources
- Can view all users and orders
- Can create/update/delete inventory and promotions

This implementation provides a secure, role-based access control system that properly separates customer and administrative functionality.
